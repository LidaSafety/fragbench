#!/usr/bin/env python3
"""For each attack-graph fragment that does NOT pass MCP, record why.

Failure categories:
  - session_missing : resolved session_path does not exist on disk
  - parse_error     : session jsonl could not be parsed
  - no_tool_calls   : session has zero tool_call/tool_result events
  - tool_failed     : one or more tool_result.success != True

For tool_failed we attach the failing tool name, truncated arguments,
and the truncated result_preview (which usually contains the error string).
We also attach the verdict-event justification if present.

Output: /srv/shared/failing_fragments_by_campaign.json
"""
from __future__ import annotations
import json, sys
from collections import defaultdict
from pathlib import Path

ROOT = Path("/home/dwk/projects/fragbench2")
RUNS_DIR = ROOT / "data/graph_astha"
LOGS_DIR = ROOT / "logs"
EXTRA_LOGS_DIRS = [Path("/srv/shared/FragBench/mcp-output/sessions")]
OUT = Path("/srv/shared/failing_fragments_by_campaign.json")

ARG_TRUNC = 200
RESULT_TRUNC = 500
MAX_FAILED_CALLS_PER_FRAG = 10


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


def trunc(s, n):
    if s is None:
        return None
    s = str(s)
    return s if len(s) <= n else s[:n] + "…"


def analyse_fragment(fr: dict) -> dict | None:
    """Return None if fragment passed MCP; else a failure record."""
    sp_str = fr.get("session_path") or ""
    sp = resolve_session_path(sp_str)
    if not sp.exists():
        return {
            "reason": "session_missing",
            "session_path": sp_str,
            "resolved_path": str(sp),
        }
    try:
        events = parse_concatenated_json(sp.read_text())
    except (OSError, json.JSONDecodeError) as e:
        return {
            "reason": "parse_error",
            "session_path": sp_str,
            "resolved_path": str(sp),
            "error": str(e),
        }

    calls = [e for e in events if e.get("event") == "tool_call"]
    results = [e for e in events if e.get("event") == "tool_result"]
    verdict_ev = next((e for e in events if e.get("event") == "verdict"), None)

    if not calls and not results:
        rec = {
            "reason": "no_tool_calls",
            "session_path": sp_str,
            "n_events": len(events),
        }
        if verdict_ev:
            rec["verdict"] = verdict_ev.get("verdict")
            rec["verdict_justification"] = trunc(verdict_ev.get("justification"), 400)
        return rec

    failed = [r for r in results if r.get("success") is not True]
    if not failed and results:
        return None  # passed

    # Either there are explicit failed tool_results, or there were calls but no results
    rec = {
        "reason": "tool_failed" if failed else "no_tool_results",
        "session_path": sp_str,
        "n_tool_calls": len(calls),
        "n_tool_results": len(results),
        "n_failed": len(failed),
    }
    if verdict_ev:
        rec["verdict"] = verdict_ev.get("verdict")
        rec["verdict_justification"] = trunc(verdict_ev.get("justification"), 400)

    # Build per-call failure list
    call_by_idx: dict = {}
    for c in calls:
        idx = c.get("tool_call_index")
        if idx is not None:
            call_by_idx[str(idx)] = c

    failed_records = []
    for r in failed[:MAX_FAILED_CALLS_PER_FRAG]:
        idx = r.get("tool_result_index")  # e.g. "1/1"
        c = None
        if idx and "/" in str(idx):
            c = call_by_idx.get(str(idx).split("/")[0])
        failed_records.append({
            "tool": r.get("tool"),
            "tool_result_index": idx,
            "iteration": r.get("iteration"),
            "result_preview": trunc(r.get("result_preview"), RESULT_TRUNC),
            "arguments_preview": trunc(c.get("arguments") if c else None, ARG_TRUNC),
        })
    rec["failed_calls"] = failed_records
    if len(failed) > MAX_FAILED_CALLS_PER_FRAG:
        rec["failed_calls_truncated"] = len(failed) - MAX_FAILED_CALLS_PER_FRAG
    return rec


def main():
    graph_files = sorted(RUNS_DIR.glob("attack_graph_*_seed_*_*.json"))
    print(f"scanning {len(graph_files)} graph files", file=sys.stderr)

    campaigns: dict[str, dict] = defaultdict(lambda: {
        "campaign": None,
        "campaign_id": None,
        "n_fragments_total": 0,
        "n_fragments_failed": 0,
        "by_reason": defaultdict(int),
        "fragments": [],
    })

    for gf in graph_files:
        try:
            g = json.loads(gf.read_text())
        except json.JSONDecodeError:
            continue
        v = g.get("variation") or {}
        campaign = v.get("campaign") or g.get("campaign")
        campaign_id = v.get("campaign_id")
        run_id = g.get("run_id")
        seed = v.get("seed")
        key = campaign or campaign_id or "<unknown>"
        frags = v.get("fragments") or []
        if not frags:
            continue

        c = campaigns[key]
        c["campaign"] = campaign
        c["campaign_id"] = campaign_id or c["campaign_id"]

        for fr in frags:
            c["n_fragments_total"] += 1
            failure = analyse_fragment(fr)
            if failure is None:
                continue
            c["n_fragments_failed"] += 1
            c["by_reason"][failure["reason"]] += 1
            c["fragments"].append({
                "fragment_id": fr.get("fragment_id"),
                "fragment_index": fr.get("fragment_index"),
                "phase": fr.get("phase"),
                "role": fr.get("role"),
                "is_cover": fr.get("is_cover"),
                "passed_judge": fr.get("passed"),
                "judge_verdict": fr.get("verdict"),
                "judge_justification": trunc(fr.get("justification"), 300),
                "run_id": run_id,
                "seed": seed,
                "attack_graph_file": gf.name,
                "prompt_preview": trunc(fr.get("prompt"), 300),
                **failure,
            })

    # Convert defaultdicts to plain dicts and finalise
    out_campaigns = []
    grand_total = 0
    grand_failed = 0
    grand_by_reason = defaultdict(int)
    for key, c in sorted(campaigns.items()):
        grand_total += c["n_fragments_total"]
        grand_failed += c["n_fragments_failed"]
        for k, n in c["by_reason"].items():
            grand_by_reason[k] += n
        out_campaigns.append({
            "campaign": c["campaign"] or key,
            "campaign_id": c["campaign_id"],
            "n_fragments_total": c["n_fragments_total"],
            "n_fragments_failed": c["n_fragments_failed"],
            "pct_failed": round(100.0 * c["n_fragments_failed"] / c["n_fragments_total"], 2)
                          if c["n_fragments_total"] else 0.0,
            "by_reason": dict(c["by_reason"]),
            "failed_fragments": c["fragments"],
        })

    out = {
        "definition": {
            "failure_reasons": {
                "session_missing": "resolved session_path does not exist",
                "parse_error": "session jsonl could not be parsed",
                "no_tool_calls": "session has zero tool_call/tool_result events (model never invoked any MCP tool)",
                "no_tool_results": "tool_call(s) present but no tool_result events",
                "tool_failed": "one or more tool_result.success != true",
            },
            "trunc": {
                "arguments_preview_chars": ARG_TRUNC,
                "result_preview_chars": RESULT_TRUNC,
                "max_failed_calls_per_fragment": MAX_FAILED_CALLS_PER_FRAG,
            },
            "source_graph_dir": str(RUNS_DIR),
            "n_graph_files": len(graph_files),
        },
        "summary": {
            "n_fragments_total": grand_total,
            "n_fragments_failed": grand_failed,
            "pct_failed": round(100.0 * grand_failed / grand_total, 2) if grand_total else 0.0,
            "by_reason": dict(grand_by_reason),
        },
        "campaigns": out_campaigns,
    }
    OUT.write_text(json.dumps(out, indent=2))
    print(f"wrote {OUT} ({OUT.stat().st_size:,} bytes)", file=sys.stderr)
    print(f"  fragments total: {grand_total}, failed: {grand_failed}", file=sys.stderr)
    for k, n in sorted(grand_by_reason.items(), key=lambda kv: -kv[1]):
        print(f"    {k}: {n}", file=sys.stderr)


if __name__ == "__main__":
    main()
