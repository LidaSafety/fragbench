#!/usr/bin/env python3
"""Aggregate per-campaign fragment counts and execution-success counts.

Sources mirror /home/dwk/projects/fragbench2/data/nice4/_build.py:
  - data/graph_astha/attack_graph_*_seed_*_*.json   (chain definitions)
  - resolve session_path -> (path | logs/<base> | /srv/shared/FragBench/mcp-output/sessions/<base>)

Per fragment we compute:
  - passed_judge:  variation.fragments[i].passed  (judge verdict from attack graph)
  - exec_ok:       all tool_result.success == True AND at least one tool_call/result present
                   in the resolved session jsonl

Aggregated per `campaign` (falling back to campaign_id when missing).
"""
from __future__ import annotations
import json, sys
from collections import defaultdict
from pathlib import Path

ROOT = Path("/home/dwk/projects/fragbench2")
RUNS_DIR = ROOT / "data/graph_astha"
LOGS_DIR = ROOT / "logs"
EXTRA_LOGS_DIRS = [Path("/srv/shared/FragBench/mcp-output/sessions")]
OUT = Path("/srv/shared/campaign_fragment_success.json")


def parse_concatenated_json(text: str):
    if not text.strip():
        return []
    dec = json.JSONDecoder(strict=False)
    out, i = [], 0
    while i < len(text):
        while i < len(text) and text[i] in " \t\n\r":
            i += 1
        if i >= len(text):
            break
        obj, e = dec.raw_decode(text, i)
        out.append(obj)
        i = e
    return out


def resolve_session_path(p: str) -> Path:
    if not p:
        return Path("/dev/null")
    cands: list[Path] = []
    if p.startswith("/app/"):
        cands.append(ROOT / p[len("/app/"):])
    elif p.startswith("/"):
        cands.append(Path(p))
    else:
        cands.append(ROOT / p)
    base = Path(p).name
    cands.append(LOGS_DIR / base)
    for d in EXTRA_LOGS_DIRS:
        cands.append(d / base)
    for c in cands:
        if c.exists():
            return c
    return cands[0]


def fragment_exec_ok(session_path: Path) -> tuple[bool, int, int]:
    """Return (exec_ok, n_tool_calls, n_tool_success)."""
    if not session_path.exists():
        return (False, 0, 0)
    try:
        events = parse_concatenated_json(session_path.read_text())
    except (OSError, json.JSONDecodeError):
        return (False, 0, 0)
    n_calls = sum(1 for e in events if e.get("event") == "tool_call")
    results = [e for e in events if e.get("event") == "tool_result"]
    n_success = sum(1 for e in results if e.get("success") is True)
    if not results:
        return (False, n_calls, 0)
    exec_ok = all(e.get("success") is True for e in results)
    return (exec_ok, n_calls, n_success)


def main():
    graph_files = sorted(RUNS_DIR.glob("attack_graph_*_seed_*_*.json"))
    print(f"found {len(graph_files)} graph files", file=sys.stderr)

    # campaign -> aggregator
    agg: dict[str, dict] = defaultdict(lambda: {
        "campaign": None,
        "campaign_id": None,
        "n_chains": 0,
        "n_fragments": 0,
        "n_exec_ok": 0,
        "n_passed_judge": 0,
        "n_session_missing": 0,
        "n_no_tool_results": 0,
        "n_tool_calls_total": 0,
        "n_tool_calls_success": 0,
    })

    for gf in graph_files:
        try:
            g = json.loads(gf.read_text())
        except json.JSONDecodeError:
            continue
        v = g.get("variation") or {}
        campaign = v.get("campaign") or g.get("campaign")
        campaign_id = v.get("campaign_id")
        key = campaign or campaign_id or "<unknown>"
        frags = v.get("fragments") or []
        if not frags:
            continue

        a = agg[key]
        a["campaign"] = campaign
        a["campaign_id"] = campaign_id or a["campaign_id"]
        a["n_chains"] += 1

        for fr in frags:
            a["n_fragments"] += 1
            if fr.get("passed") is True:
                a["n_passed_judge"] += 1
            sp = resolve_session_path(fr.get("session_path") or "")
            if not sp.exists():
                a["n_session_missing"] += 1
                continue
            ok, n_calls, n_succ = fragment_exec_ok(sp)
            a["n_tool_calls_total"] += n_calls
            a["n_tool_calls_success"] += n_succ
            if n_calls == 0:
                a["n_no_tool_results"] += 1
            if ok:
                a["n_exec_ok"] += 1

    # Build output rows
    rows = []
    totals = defaultdict(int)
    for key, a in sorted(agg.items()):
        nf = a["n_fragments"]
        pct = (100.0 * a["n_exec_ok"] / nf) if nf else 0.0
        pct_judge = (100.0 * a["n_passed_judge"] / nf) if nf else 0.0
        rows.append({
            "campaign": a["campaign"] or key,
            "campaign_id": a["campaign_id"],
            "n_chains": a["n_chains"],
            "n_fragments": nf,
            "n_fragments_exec_ok": a["n_exec_ok"],
            "pct_fragments_exec_ok": round(pct, 2),
            "n_fragments_passed_judge": a["n_passed_judge"],
            "pct_fragments_passed_judge": round(pct_judge, 2),
            "n_session_missing": a["n_session_missing"],
            "n_fragments_no_tool_results": a["n_no_tool_results"],
            "n_tool_calls_total": a["n_tool_calls_total"],
            "n_tool_calls_success": a["n_tool_calls_success"],
        })
        for k in ("n_chains", "n_fragments", "n_exec_ok", "n_passed_judge",
                 "n_session_missing", "n_no_tool_results",
                 "n_tool_calls_total", "n_tool_calls_success"):
            totals[k] += a[k]

    nf = totals["n_fragments"]
    summary = {
        "n_campaigns": len(rows),
        "n_chains": totals["n_chains"],
        "n_fragments": nf,
        "n_fragments_exec_ok": totals["n_exec_ok"],
        "pct_fragments_exec_ok": round(100.0 * totals["n_exec_ok"] / nf, 2) if nf else 0.0,
        "n_fragments_passed_judge": totals["n_passed_judge"],
        "pct_fragments_passed_judge": round(100.0 * totals["n_passed_judge"] / nf, 2) if nf else 0.0,
        "n_session_missing": totals["n_session_missing"],
        "n_fragments_no_tool_results": totals["n_no_tool_results"],
        "n_tool_calls_total": totals["n_tool_calls_total"],
        "n_tool_calls_success": totals["n_tool_calls_success"],
    }

    out = {
        "definition": {
            "exec_ok": "fragment counted successful iff session file exists, has ≥1 tool_result event, and every tool_result has success==true",
            "passed_judge": "variation.fragments[i].passed from attack_graph_*.json (judge verdict)",
            "source_graph_dir": str(RUNS_DIR),
            "n_graph_files": len(graph_files),
        },
        "summary": summary,
        "campaigns": rows,
    }
    OUT.write_text(json.dumps(out, indent=2))
    print(f"wrote {OUT} ({OUT.stat().st_size:,} bytes, {len(rows)} campaigns)", file=sys.stderr)


if __name__ == "__main__":
    main()
