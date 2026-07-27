#!/usr/bin/env python3
"""Summarise executed-benign chains: per-fragment verdicts and the axes that
decide whether the control set is usable.

Reports, per campaign, the fragment pass/fail pattern, and across the sweep the
two rates that matter for parity with the malicious side (measured there as
26.6% fragment-verdict failures and 3.7% tool-result failures), plus the share of
reads a chain satisfies from its own writes.

Read that last figure carefully. Since the shared artifact tier landed, a chain
reading another chain's file is partly *intended*: the reference stems in
SHARED_ARTIFACTS carry bare names precisely so chains share resources the way the
malicious corpus does. A falling own-chain share is therefore expected as the grid
accumulates, and is only a problem if it comes with a rising tool-result failure
rate, which is the signal that concurrent variations are clobbering each other.

    python scripts/summarize_benign_run.py                    # all benign runs
    python scripts/summarize_benign_run.py --since DIR_OR_TS  # only newer runs
    python scripts/summarize_benign_run.py --run-id RUNID     # one harness run
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re

READ = {"read_file", "read_file_bytes"}
WRITE = {"write_file", "append_file", "edit_file"}


def norm(p: str) -> str:
    return os.path.basename(str(p).replace("\\", "/").rstrip("/"))


def paths_of(arg) -> list[str]:
    if not isinstance(arg, str):
        arg = json.dumps(arg)
    s = arg.strip()
    if s.startswith("{"):
        return re.findall(r'"path"\s*:\s*"([^"]+)"', s)
    return [s] if s else []


_LOG_INDEX: dict[str, str] | None = None


def _log_index() -> dict[str, str]:
    """Map session-log basename -> path, searching logs/ recursively.

    The harness files sessions under logs/<run_id>/ and older runs sit in
    logs/old/, so a flat logs/<basename> lookup silently finds nothing and
    every tool-result rate reads zero while the verdict counts still work.
    """
    global _LOG_INDEX
    if _LOG_INDEX is None:
        _LOG_INDEX = {
            os.path.basename(p): p
            for p in glob.glob("logs/**/session_*.jsonl", recursive=True)
        }
    return _LOG_INDEX


def session_events(fragment: dict):
    """Yield (tool, paths, ok) once per resolved tool call in a fragment.

    One event per call, including calls that carry no path (glob_files,
    list_directory by pattern), so the failure rate shares the denominator the
    malicious 3.7% baseline was measured over.
    """
    sp = fragment.get("session_path")
    if not sp:
        return
    p = _log_index().get(os.path.basename(sp))
    if not p:
        return
    pending: tuple[str, list[str]] | None = None
    with open(p) as fh:
        for line in fh:
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            ev = e.get("event")
            if ev == "tool_call":
                pending = (e.get("tool"), paths_of(e.get("arguments")))
            elif ev == "tool_result":
                # Count off the result event itself -- some results arrive
                # without a paired call in the stream, and dropping those would
                # shrink the denominator the failure rate is measured over.
                tool = e.get("tool")
                paths = pending[1] if pending and pending[0] == tool else []
                yield tool, paths, e.get("success") is not False
                pending = None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--since", help="only runs newer than this path's mtime, or a run-id substring")
    ap.add_argument("--run-id", help="only this harness run id")
    args = ap.parse_args()

    # recursive: run files are sometimes filed into results/runs/<subdir>/
    graphs = sorted(glob.glob("results/runs/**/attack_graph_*BENIGN*.json",
                              recursive=True),
                    key=os.path.getmtime)
    if args.run_id:
        graphs = [g for g in graphs if args.run_id in g]
    if args.since:
        if os.path.exists(args.since):
            # A directory's own mtime tracks its *last* write, so anchoring on
            # it would match only the final run of a sweep. Anchor on the
            # oldest entry instead -- that is when the sweep started.
            if os.path.isdir(args.since):
                entries = [os.path.join(args.since, e) for e in os.listdir(args.since)]
                cutoff = min((os.path.getmtime(e) for e in entries),
                             default=os.path.getmtime(args.since))
            else:
                cutoff = os.path.getmtime(args.since)
            graphs = [g for g in graphs if os.path.getmtime(g) >= cutoff]
        else:
            graphs = [g for g in graphs if args.since in g]

    if not graphs:
        print("no matching benign runs found")
        return 1

    rows, tot_f, bad_f, tot_r, bad_r, own, out = [], 0, 0, 0, 0, 0, 0
    for g in graphs:
        d = json.load(open(g))
        v = d["variation"]
        frags = v.get("fragments") or []
        if not frags:
            continue
        verdicts = [f.get("verdict", "?") for f in frags]
        tot_f += len(verdicts)
        bad_f += sum(1 for x in verdicts if x != "PASS")

        written: set[str] = set()
        for f in frags:
            for tool, pas, ok in session_events(f):
                tot_r += 1
                if not ok:
                    bad_r += 1
                    continue
                for pa in pas:
                    if tool in READ:
                        own_hit = norm(pa) in written
                        own += own_hit
                        out += not own_hit
                    elif tool in WRITE:
                        written.add(norm(pa))
        rows.append((v.get("campaign", "?"), v.get("seed"), verdicts))

    width = max(len(r[0]) for r in rows)
    for camp, seed, verdicts in rows:
        bad = sum(1 for x in verdicts if x != "PASS")
        mark = "ok  " if bad == 0 else f"{bad} FAIL"
        pattern = "".join("." if x == "PASS" else "X" for x in verdicts)
        print(f"  {camp:<{width}}  seed {seed:<4} {len(verdicts):>2} frags  {pattern:<16} {mark}")

    print(f"\n  chains={len(rows)}")
    print(f"  fragment verdicts : {bad_f}/{tot_f} FAIL "
          f"({100*bad_f/max(tot_f,1):.1f}%)   malicious corpus: 26.6%")
    print(f"  tool results      : {bad_r}/{tot_r} failed "
          f"({100*bad_r/max(tot_r,1):.1f}%)   malicious corpus: 3.7%")
    reads = own + out
    print(f"  reads own-chain   : {own}/{reads} "
          f"({100*own/max(reads,1):.0f}%)   malicious corpus: 55%")
    print("  (own-chain below malicious is expected: the shared artifact tier is")
    print("   meant to be read across chains. Worry only if tool-result failures rise.)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
