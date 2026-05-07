#!/usr/bin/env python3
"""For each tool_failed fragment in graph_astha, classify its predecessor in
the chain (passed / no_tool_calls / tool_failed / no_tool_results /
session_missing / parse_error / first_in_chain) so we can see how often a
tool_failed is plausibly caused by an upstream miss.

Also surfaces the produces/consumes link: was the current fragment trying to
consume an artifact the previous fragment was supposed to produce?

Output: /srv/shared/cascading_failures_graph_astha.json
"""
from __future__ import annotations
import json, sys
from collections import defaultdict
from pathlib import Path

ROOT = Path("/home/dwk/projects/fragbench2")
RUNS_DIR = ROOT / "data/graph_astha"
LOGS_DIR = ROOT / "logs"
EXTRA_LOGS_DIRS = [Path("/srv/shared/FragBench/mcp-output/sessions")]
OUT = Path("/srv/shared/cascading_failures_graph_astha.json")

RESULT_TRUNC = 400


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


def fragment_status(fr: dict) -> tuple[str, list[dict]]:
    """Return (status, failed_calls_records)."""
    sp = resolve_session_path(fr.get("session_path") or "")
    if not sp.exists():
        return ("session_missing", [])
    try:
        events = parse_concatenated_json(sp.read_text())
    except (OSError, json.JSONDecodeError):
        return ("parse_error", [])
    calls = [e for e in events if e.get("event") == "tool_call"]
    results = [e for e in events if e.get("event") == "tool_result"]
    if not calls and not results:
        return ("no_tool_calls", [])
    failed = [r for r in results if r.get("success") is not True]
    if not failed and results:
        return ("passed", [])
    if not results:
        return ("no_tool_results", [])
    # build lightweight failed_call records
    call_by_idx = {}
    for c in calls:
        i = c.get("tool_call_index")
        if i is not None:
            call_by_idx[str(i)] = c
    fr_records = []
    for r in failed[:5]:
        idx = r.get("tool_result_index")
        c = None
        if idx and "/" in str(idx):
            c = call_by_idx.get(str(idx).split("/")[0])
        fr_records.append({
            "tool": r.get("tool"),
            "result_preview": trunc(r.get("result_preview"), RESULT_TRUNC),
            "arguments_preview": trunc(c.get("arguments") if c else None, 150),
        })
    return ("tool_failed", fr_records)


def main():
    graph_files = sorted(RUNS_DIR.glob("attack_graph_*_seed_*_*.json"))
    print(f"scanning {len(graph_files)} graph files", file=sys.stderr)

    campaigns: dict[str, dict] = defaultdict(lambda: {
        "campaign": None,
        "n_tool_failed": 0,
        "n_first_in_chain": 0,
        "n_after_passed": 0,
        "n_after_failed": 0,
        "previous_failure_reasons": defaultdict(int),
        "n_artifact_link": 0,  # current.consumes ∩ previous.produces non-empty
        "fragments": [],
    })

    grand = {
        "n_tool_failed": 0,
        "n_first_in_chain": 0,
        "n_after_passed": 0,
        "n_after_failed": 0,
        "previous_failure_reasons": defaultdict(int),
        "n_artifact_link": 0,
    }

    for gf in graph_files:
        try:
            g = json.loads(gf.read_text())
        except json.JSONDecodeError:
            continue
        v = g.get("variation") or {}
        campaign = v.get("campaign") or g.get("campaign")
        run_id = g.get("run_id")
        seed = v.get("seed")
        frags = v.get("fragments") or []
        if not frags:
            continue
        # Sort by fragment_index just in case
        frags = sorted(frags, key=lambda fr: fr.get("fragment_index") or 0)

        # Compute status for every fragment in chain
        statuses: list[tuple[str, list[dict]]] = [fragment_status(fr) for fr in frags]

        for i, fr in enumerate(frags):
            status, failed_calls = statuses[i]
            if status != "tool_failed":
                continue
            key = campaign or "<unknown>"
            c = campaigns[key]
            c["campaign"] = campaign
            c["n_tool_failed"] += 1
            grand["n_tool_failed"] += 1

            prev_idx = i - 1
            if prev_idx < 0:
                c["n_first_in_chain"] += 1
                grand["n_first_in_chain"] += 1
                prev_status = "first_in_chain"
                prev_frag = None
                artifact_overlap = []
            else:
                prev_frag = frags[prev_idx]
                prev_status = statuses[prev_idx][0]
                if prev_status == "passed":
                    c["n_after_passed"] += 1
                    grand["n_after_passed"] += 1
                else:
                    c["n_after_failed"] += 1
                    grand["n_after_failed"] += 1
                    c["previous_failure_reasons"][prev_status] += 1
                    grand["previous_failure_reasons"][prev_status] += 1
                cur_cons = set(fr.get("consumes") or [])
                prev_prod = set(prev_frag.get("produces") or [])
                artifact_overlap = sorted(cur_cons & prev_prod)
                if artifact_overlap:
                    c["n_artifact_link"] += 1
                    grand["n_artifact_link"] += 1

            c["fragments"].append({
                "fragment_id": fr.get("fragment_id"),
                "fragment_index": fr.get("fragment_index"),
                "phase": fr.get("phase"),
                "role": fr.get("role"),
                "is_cover": fr.get("is_cover"),
                "consumes": fr.get("consumes") or [],
                "passed_judge": fr.get("passed"),
                "judge_verdict": fr.get("verdict"),
                "run_id": run_id,
                "seed": seed,
                "attack_graph_file": gf.name,
                "current_failed_calls": failed_calls,
                "previous_status": prev_status,
                "previous_fragment_id": prev_frag.get("fragment_id") if prev_frag else None,
                "previous_fragment_index": prev_frag.get("fragment_index") if prev_frag else None,
                "previous_role": prev_frag.get("role") if prev_frag else None,
                "previous_produces": (prev_frag.get("produces") or []) if prev_frag else [],
                "previous_passed_judge": prev_frag.get("passed") if prev_frag else None,
                "artifact_overlap": artifact_overlap,
            })

    # finalise
    out_campaigns = []
    for key, c in sorted(campaigns.items()):
        nt = c["n_tool_failed"]
        out_campaigns.append({
            "campaign": c["campaign"] or key,
            "n_tool_failed": nt,
            "n_first_in_chain": c["n_first_in_chain"],
            "n_after_passed": c["n_after_passed"],
            "n_after_failed": c["n_after_failed"],
            "pct_after_failed": round(100.0 * c["n_after_failed"] / nt, 2) if nt else 0.0,
            "n_artifact_link": c["n_artifact_link"],
            "pct_artifact_link": round(100.0 * c["n_artifact_link"] / nt, 2) if nt else 0.0,
            "previous_failure_reasons": dict(c["previous_failure_reasons"]),
            "tool_failed_fragments": c["fragments"],
        })

    nt = grand["n_tool_failed"]
    summary = {
        "n_tool_failed": nt,
        "n_first_in_chain": grand["n_first_in_chain"],
        "n_after_passed": grand["n_after_passed"],
        "n_after_failed": grand["n_after_failed"],
        "pct_after_failed": round(100.0 * grand["n_after_failed"] / nt, 2) if nt else 0.0,
        "n_artifact_link": grand["n_artifact_link"],
        "pct_artifact_link": round(100.0 * grand["n_artifact_link"] / nt, 2) if nt else 0.0,
        "previous_failure_reasons": dict(grand["previous_failure_reasons"]),
    }

    out = {
        "definition": {
            "scope": "every fragment classified as tool_failed in graph_astha",
            "previous_status": "exec status of the chain's fragment_index-1 neighbour (same statuses as failure_reasons + 'passed' + 'first_in_chain')",
            "artifact_link": "true iff (current.consumes ∩ previous.produces) is non-empty — i.e., a missing upstream artifact could plausibly be the cause",
            "source_graph_dir": str(RUNS_DIR),
            "n_graph_files": len(graph_files),
        },
        "summary": summary,
        "campaigns": out_campaigns,
    }
    OUT.write_text(json.dumps(out, indent=2))
    print(f"wrote {OUT} ({OUT.stat().st_size:,} bytes)", file=sys.stderr)
    print(f"  tool_failed={nt}: after_passed={grand['n_after_passed']}, after_failed={grand['n_after_failed']}, first_in_chain={grand['n_first_in_chain']}", file=sys.stderr)
    print(f"  with artifact link to prev frag: {grand['n_artifact_link']}", file=sys.stderr)
    print(f"  prev failure breakdown: {dict(grand['previous_failure_reasons'])}", file=sys.stderr)


if __name__ == "__main__":
    main()
