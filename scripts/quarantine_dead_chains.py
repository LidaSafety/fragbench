#!/usr/bin/env python3
"""Move chains containing zero-tool-call sessions out of results/runs/.

An API-limit casualty writes a complete-looking session with no tool calls in
it, so the chain's graph file passes every existing check. Re-running the
campaign produces a *new* chain rather than replacing the broken one, so the
dead chains have to be moved aside or the corpus keeps both.

Moves rather than deletes: the broken chains are the evidence for what happened
and how much was lost, which belongs in the run's provenance rather than the
bin. Nothing is removed from logs/ -- session filenames are unique, so stale
logs are inert once their graph is gone.

    python scripts/quarantine_dead_chains.py --dry-run   # what would move
    python scripts/quarantine_dead_chains.py             # move them
    python scripts/quarantine_dead_chains.py --markers   # run_state to clear
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import shutil
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

STYLE_OF_MARKER = {}  # (campaign, style) -> marker filename


def dead_session_names() -> set[str]:
    dead = set()
    for path in glob.glob(str(REPO / "logs" / "**" / "session_*.jsonl"), recursive=True):
        calls = ended = False
        try:
            for line in open(path):
                if '"tool_call"' in line:
                    calls = True
                    break
                if '"session_end"' in line:
                    ended = True
        except OSError:
            continue
        if not calls and ended:
            dead.add(os.path.basename(path))
    return dead


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--markers", action="store_true",
                    help="print the run_state markers to clear, then exit")
    ap.add_argument("--quarantine", default="results/quarantine_dead")
    args = ap.parse_args()

    dead = dead_session_names()
    print(f"zero-tool-call sessions: {len(dead):,}")

    affected = []          # (graph_path, campaign, style, seed, n_dead)
    combos = defaultdict(set)
    for g in glob.glob(str(REPO / "results" / "runs" / "**" /
                           "attack_graph_*BENIGN*.json"), recursive=True):
        try:
            v = json.load(open(g))["variation"]
        except Exception:
            continue
        frags = v.get("fragments") or []
        n = sum(1 for f in frags
                if os.path.basename(str(f.get("session_path"))) in dead)
        if n:
            camp, style = v.get("campaign", "?"), v.get("style", "?")
            affected.append((g, camp, style, v.get("seed"), n))
            combos[(camp, style)].add(v.get("seed"))

    if not affected:
        print("nothing to quarantine")
        return 0

    if args.markers:
        print(f"\n# clear these on the instance that ran them ({len(combos)} blocks)")
        names = sorted({f"{c.lower()}__{s}.done" for (c, s) in combos})
        print("rm -f \\")
        for n in names:
            print(f"  run_state/{n} \\")
        print("  ;")
        return 0

    print(f"chains to quarantine: {len(affected)}  "
          f"(fragments lost: {sum(a[4] for a in affected)})")
    for (camp, style), seeds in sorted(combos.items()):
        print(f"  {camp[7:]:<26}{style:<18}seeds {','.join(map(str, sorted(seeds)))}")

    if args.dry_run:
        print("\n(dry run -- nothing moved)")
        return 0

    dest = REPO / args.quarantine
    dest.mkdir(parents=True, exist_ok=True)
    moved = 0
    for g, *_ in affected:
        gp = Path(g)
        # a chain is graph + chain + meta, all sharing the run-id stem
        stem = gp.name.replace("attack_graph_", "attack_", 1)[:-len(".json")]
        for sibling in gp.parent.glob(stem.split("_seed_")[0] + "*"):
            if sibling.is_file():
                target = dest / sibling.name
                if not target.exists():
                    shutil.move(str(sibling), str(target))
                    moved += 1
        if gp.exists():
            shutil.move(str(gp), str(dest / gp.name))
            moved += 1

    print(f"\nmoved {moved} files -> {dest}")
    print("run with --markers for the run_state lines to clear on the instances")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
