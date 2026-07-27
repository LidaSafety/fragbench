#!/usr/bin/env python3
"""Emit dataset/nice1-style benign.json from the executed-benign corpus.

The point of the executed control set is that benign and malicious traces are
produced by the same harness, so they should also be *parsed* by the same code.
This script therefore does not reimplement event extraction: it stages the
benign runs into the {runs,logs} layout that normalize_dataset.build_malicious
already understands, calls that function, and relabels the result.

Two things it has to handle that the released corpora do not:

  * session logs live under logs/<run_id>/ and logs/old/, not flat, so they are
    symlinked into a staging directory;
  * the corpus contains early smoke and pilot chains that ran with JUDGE=1 and
    pre-cap seeds, which must not enter the dataset -- hence --since.

    python scripts/build_executed_benign_json.py --out benign.json
    python scripts/build_executed_benign_json.py --out benign.json --sample 143
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import random
from collections import defaultdict
import re
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
NORMALIZER = REPO / "fragbench-structural-graph-main" / "dataset"

# The EC2 grid began on 2026-07-26; everything before it is smoke/pilot output
# that ran with JUDGE=1 and the pre-cap seeds.
DEFAULT_SINCE = "20260726_1000"

_RUN_TS = re.compile(r"attack_graph_(\d{8}_\d{6})_")


def run_timestamp(path: str) -> str | None:
    m = _RUN_TS.search(os.path.basename(path))
    return m.group(1) if m else None


def dead_sessions(log_index: dict[str, str]) -> set[str]:
    """Session logs that recorded no tool call at all.

    When the API key hits its limit the harness still writes a session:
    start, toolkits_connected, user_query, iteration_start, end -- and no tool
    calls. The chain's graph file looks normal, so these do not show up as
    failures; they show up as fragments that silently did nothing.
    """
    dead = set()
    for base, path in log_index.items():
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
            dead.add(base)
    return dead


def stage(graphs: list[str], staging: Path) -> int:
    """Symlink graphs and their session logs into a flat {runs,logs} layout."""
    runs, logs = staging / "runs", staging / "logs"
    if staging.exists():
        shutil.rmtree(staging)
    runs.mkdir(parents=True)
    logs.mkdir(parents=True)

    log_index = {
        os.path.basename(p): os.path.abspath(p)
        for p in glob.glob(str(REPO / "logs" / "**" / "session_*.jsonl"), recursive=True)
    }

    linked = 0
    for g in graphs:
        (runs / os.path.basename(g)).symlink_to(os.path.abspath(g))
        try:
            frags = json.load(open(g))["variation"].get("fragments") or []
        except Exception as e:
            print(f"  warn: {os.path.basename(g)} unreadable: {e}", file=sys.stderr)
            continue
        for f in frags:
            base = os.path.basename(str(f.get("session_path") or ""))
            src = log_index.get(base)
            if not src:
                continue
            dst = logs / base
            if not dst.exists():
                dst.symlink_to(src)
                linked += 1
    return linked


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="benign_executed.json", help="output json path")
    ap.add_argument("--since", default=DEFAULT_SINCE,
                    help=f"keep runs at/after this YYYYMMDD_HHMMSS (default {DEFAULT_SINCE})")
    ap.add_argument("--sample", type=int,
                    help="keep only N chains, for matching the prior of the "
                         "synthetic benign control (143 samples in nice1)")
    ap.add_argument("--seed", type=int, default=0, help="sampling seed")
    ap.add_argument("--staging", default="dataset_staging/executed_benign")
    ap.add_argument("--keep-dead", action="store_true",
                    help="keep chains containing zero-tool-call sessions "
                         "(API-limit casualties); excluded by default")
    ap.add_argument("--keep-duplicates", action="store_true",
                    help="keep every chain for an objective that was run more "
                         "than once; one per (campaign, style, seed) by default")
    ap.add_argument("--stratify", action="store_true",
                    help="draw --sample evenly across campaigns instead of "
                         "uniformly at random over chains")
    args = ap.parse_args()

    sys.path.insert(0, str(NORMALIZER))
    try:
        from normalize_dataset import build_malicious
    except ImportError as e:
        print(f"cannot import normalize_dataset from {NORMALIZER}: {e}", file=sys.stderr)
        return 1

    graphs = sorted(glob.glob(
        str(REPO / "results" / "runs" / "**" / "attack_graph_*BENIGN*.json"),
        recursive=True))
    total = len(graphs)
    graphs = [g for g in graphs if (ts := run_timestamp(g)) and ts >= args.since]
    print(f"benign graphs: {total} found, {len(graphs)} at/after {args.since}")

    log_index = {
        os.path.basename(p): os.path.abspath(p)
        for p in glob.glob(str(REPO / "logs" / "**" / "session_*.jsonl"), recursive=True)
    }
    if not args.keep_dead:
        dead = dead_sessions(log_index)
        kept = []
        dropped = 0
        for g in graphs:
            try:
                frags = json.load(open(g))["variation"].get("fragments") or []
            except Exception:
                continue
            if any(os.path.basename(str(f.get("session_path"))) in dead for f in frags):
                dropped += 1
            else:
                kept.append(g)
        graphs = kept
        print(f"  dropped {dropped} chains containing zero-tool-call sessions "
              f"-> {len(graphs)} usable")

    # (campaign, style, seed) identifies an objective; the run id does not.
    triple: dict[str, tuple] = {}
    for g in graphs:
        try:
            v = json.load(open(g))["variation"]
        except Exception:
            continue
        triple[g] = (v.get("campaign"), v.get("style"), v.get("seed"))

    if not args.keep_duplicates:
        # Re-running a block after the API-limit window produced a second chain
        # for objectives that already had a good one. Two runs of the same
        # objective are redundancy, not data -- and they inflate whichever
        # campaign happened to need re-running. Newest run id wins.
        best: dict[tuple, str] = {}
        for g in graphs:
            k = triple.get(g)
            if k and (k not in best or g > best[k]):
                best[k] = g
        dropped = len(graphs) - len(best)
        graphs = sorted(best.values())
        print(f"  dropped {dropped} repeat chains -> {len(graphs)} distinct objectives")

    if args.sample and args.sample < len(graphs):
        rng = random.Random(args.seed)
        if args.stratify:
            # Round-robin across campaigns. A flat draw leaves campaign counts
            # anywhere from 11 to 32 by luck, while the malicious side is
            # uniform at ~24 per campaign; an imbalanced control set is an
            # easy thing for a reviewer to object to.
            by_campaign: dict[str, list[str]] = defaultdict(list)
            for g in graphs:
                by_campaign[triple[g][0]].append(g)
            for v in by_campaign.values():
                rng.shuffle(v)
            names = sorted(by_campaign)
            picked: list[str] = []
            depth = 0
            while len(picked) < args.sample:
                progressed = False
                for c in names:
                    if depth < len(by_campaign[c]) and len(picked) < args.sample:
                        picked.append(by_campaign[c][depth])
                        progressed = True
                if not progressed:
                    break
                depth += 1
            graphs = sorted(picked)
            print(f"  stratified sample: {len(graphs)} chains across "
                  f"{len(names)} campaigns (seed {args.seed})")
        else:
            rng.shuffle(graphs)
            graphs = sorted(graphs[:args.sample])
            print(f"  sampled down to {len(graphs)} chains (seed {args.seed})")

    if not graphs:
        print("nothing to build", file=sys.stderr)
        return 1

    staging = Path(args.staging)
    n_logs = stage(graphs, staging)
    print(f"staged {len(graphs)} graphs and {n_logs} session logs -> {staging}")

    sessions, sources = build_malicious(staging)
    n_events = sum(len(leaf) for var in sessions for leaf in var)
    n_empty = sum(1 for var in sessions for leaf in var if not leaf)
    print(f"parsed {len(sessions)} samples, {n_events} events, {n_empty} empty fragments")

    with open(args.out, "w") as f:
        json.dump({"is_malicious": False, "benign_source": sources,
                   "sessions": sessions}, f)
    print(f"wrote {args.out}  ({os.path.getsize(args.out)/1e6:.1f} MB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
