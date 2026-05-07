#!/usr/bin/env python3
"""Per-campaign list of fragments that fail MCP, source = data/malicious4.

Differences from build_failing_fragments.py (graph_astha source):
  - attack-graph schema is FLAT: run_id, seed, campaign, fragments[] live at
    top level (no `variation` wrapper). Fragment dicts do NOT carry a
    session_path; we must join sessions via (run_id, stage_index).
  - sessions live in data/malicious4/logs/, indexed by reading the
    session_start event (seq=1) of each *.jsonl file.

Failure categories: same as before
  session_missing | parse_error | no_tool_calls | no_tool_results | tool_failed
"""
from __future__ import annotations
import json, sys
from collections import defaultdict
from pathlib import Path

ROOT = Path("/home/dwk/projects/fragbench2/data/malicious4")
RUNS_DIR = ROOT / "runs"
LOGS_DIR = ROOT / "logs"
OUT = Path("/srv/shared/failing_fragments_by_campaign_malicious4.json")

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


def read_first_event(path: Path) -> dict | None:
    """Quickly grab the first JSON object (session_start) from a session file."""
    try:
        with path.open("rb") as f:
            head = f.read(8192)
    except OSError:
        return None
    text = head.decode("utf-8", errors="replace")
    text = text.lstrip()
    if not text:
        return None
    try:
        obj, _ = json.JSONDecoder(strict=False).raw_decode(text)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        return None


def trunc(s, n):
    if s is None:
        return None
    s = str(s)
    return s if len(s) <= n else s[:n] + "…"


def build_session_index() -> dict[tuple[str, int], list[Path]]:
    """(run_id, stage_index) -> list of session paths."""
    idx: dict[tuple[str, int], list[Path]] = defaultdict(list)
    n_total = 0
    n_indexed = 0
    n_no_run_id = 0
    for p in LOGS_DIR.iterdir():
        if not p.name.startswith("session_") or not p.name.endswith(".jsonl"):
            continue
        n_total += 1
        ev = read_first_event(p)
        if not ev or ev.get("event") != "session_start":
            continue
        run_id = ev.get("run_id")
        stage_index = ev.get("stage_index")
        if run_id is None or stage_index is None:
            n_no_run_id += 1
            continue
        # Some sessions also have variation_index; keep all matches under the same key.
        idx[(run_id, int(stage_index))].append(p)
        n_indexed += 1
    print(f"  indexed {n_indexed}/{n_total} session files ({n_no_run_id} without run_id/stage_index)", file=sys.stderr)
    return idx


def analyse_session(session_path: Path) -> dict:
    """Return dict with reason and detail; reason='passed' if exec_ok."""
    try:
        events = parse_concatenated_json(session_path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        return {"reason": "parse_error", "error": str(e)}

    calls = [e for e in events if e.get("event") == "tool_call"]
    results = [e for e in events if e.get("event") == "tool_result"]
    verdict_ev = next((e for e in events if e.get("event") == "verdict"), None)

    if not calls and not results:
        rec = {"reason": "no_tool_calls", "n_events": len(events)}
        if verdict_ev:
            rec["verdict"] = verdict_ev.get("verdict")
            rec["verdict_justification"] = trunc(verdict_ev.get("justification"), 400)
        return rec

    failed = [r for r in results if r.get("success") is not True]
    if not failed and results:
        return {"reason": "passed"}

    rec = {
        "reason": "tool_failed" if failed else "no_tool_results",
        "n_tool_calls": len(calls),
        "n_tool_results": len(results),
        "n_failed": len(failed),
    }
    if verdict_ev:
        rec["verdict"] = verdict_ev.get("verdict")
        rec["verdict_justification"] = trunc(verdict_ev.get("justification"), 400)

    call_by_idx: dict = {}
    for c in calls:
        i = c.get("tool_call_index")
        if i is not None:
            call_by_idx[str(i)] = c

    fr_records = []
    for r in failed[:MAX_FAILED_CALLS_PER_FRAG]:
        idx = r.get("tool_result_index")
        c = None
        if idx and "/" in str(idx):
            c = call_by_idx.get(str(idx).split("/")[0])
        fr_records.append({
            "tool": r.get("tool"),
            "tool_result_index": idx,
            "iteration": r.get("iteration"),
            "result_preview": trunc(r.get("result_preview"), RESULT_TRUNC),
            "arguments_preview": trunc(c.get("arguments") if c else None, ARG_TRUNC),
        })
    rec["failed_calls"] = fr_records
    if len(failed) > MAX_FAILED_CALLS_PER_FRAG:
        rec["failed_calls_truncated"] = len(failed) - MAX_FAILED_CALLS_PER_FRAG
    return rec


def main():
    print("=== building session index ===", file=sys.stderr)
    sess_idx = build_session_index()

    graph_files = sorted(p for p in RUNS_DIR.iterdir()
                         if p.name.startswith("attack_") and "_seed_" in p.name and p.suffix == ".json")
    print(f"=== scanning {len(graph_files)} attack-graph files ===", file=sys.stderr)

    campaigns: dict[str, dict] = defaultdict(lambda: {
        "campaign": None,
        "campaign_id": None,
        "n_fragments_total": 0,
        "n_fragments_failed": 0,
        "by_reason": defaultdict(int),
        "fragments": [],
    })

    n_skipped_graphs = 0
    for gf in graph_files:
        try:
            g = json.loads(gf.read_text())
        except json.JSONDecodeError:
            n_skipped_graphs += 1
            continue
        run_id = g.get("run_id")
        seed = g.get("seed")
        campaign = g.get("campaign")
        campaign_id = g.get("campaign_id")
        frags = g.get("fragments") or []
        if not frags or run_id is None:
            continue
        key = campaign or campaign_id or "<unknown>"
        c = campaigns[key]
        c["campaign"] = campaign
        c["campaign_id"] = campaign_id or c["campaign_id"]

        for fr in frags:
            c["n_fragments_total"] += 1
            stage_index = fr.get("fragment_index")
            sess_paths = sess_idx.get((run_id, stage_index), [])
            session_path = sess_paths[0] if sess_paths else None

            if session_path is None:
                detail = {"reason": "session_missing"}
            else:
                detail = analyse_session(session_path)

            if detail["reason"] == "passed":
                continue

            c["n_fragments_failed"] += 1
            c["by_reason"][detail["reason"]] += 1
            base = {
                "fragment_index": stage_index,
                "phase": fr.get("phase"),
                "role": fr.get("role"),
                "passed_judge": fr.get("passed"),
                "judge_verdict": fr.get("verdict"),
                "judge_justification": trunc(fr.get("justification"), 300),
                "run_id": run_id,
                "seed": seed,
                "campaign_id": campaign_id,
                "attack_graph_file": gf.name,
                "prompt_preview": trunc(fr.get("prompt"), 300),
                "session_path": str(session_path) if session_path else None,
                "n_session_candidates": len(sess_paths),
            }
            base.update(detail)
            c["fragments"].append(base)

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
            "source_runs_dir": str(RUNS_DIR),
            "source_logs_dir": str(LOGS_DIR),
            "n_graph_files": len(graph_files),
            "n_skipped_graphs": n_skipped_graphs,
            "session_match_key": "(run_id, fragment_index/stage_index)",
            "failure_reasons": {
                "session_missing": "no session jsonl indexed for (run_id, stage_index)",
                "parse_error": "session jsonl could not be parsed",
                "no_tool_calls": "session has zero tool_call/tool_result events",
                "no_tool_results": "tool_call(s) present but no tool_result events",
                "tool_failed": "one or more tool_result.success != true",
            },
            "trunc": {
                "arguments_preview_chars": ARG_TRUNC,
                "result_preview_chars": RESULT_TRUNC,
                "max_failed_calls_per_fragment": MAX_FAILED_CALLS_PER_FRAG,
            },
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
