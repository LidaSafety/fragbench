#!/usr/bin/env python3
"""Demo: take 5 fragments from variations[seed=0] of dprk_fraud_manual.json
and report MCP outcomes. Source = data/malicious4 (which uses sequential seeds
0..N matching the manual file).

Reports per fragment:
  - input prompt (parent_prompt + first style variation)
  - exec status (passed / no_tool_calls / tool_failed / ...)
  - whether a successful write_file actually happened
  - judge verdict + justification
"""
from __future__ import annotations
import json, sys
from collections import defaultdict
from pathlib import Path

ROOT = Path("/home/dwk/projects/fragbench2")
INPUT_FILE = ROOT / "results/dprk_fraud_manual.json"
M4 = ROOT / "data/malicious4"
RUNS_DIR = M4 / "runs"
LOGS_DIR = M4 / "logs"

TARGET_SEED = 0
N_FRAGMENTS = 5


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
    try:
        with path.open("rb") as f:
            head = f.read(8192)
    except OSError:
        return None
    text = head.decode("utf-8", errors="replace").lstrip()
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


def find_graph_for_seed(seed: int, campaign: str):
    """Find the latest WRAPPED attack_graph file (has variation.fragments with session_path)."""
    cap = campaign.upper()
    pat = f"attack_graph_*_seed_{seed}_{cap}_{seed}.json"
    cands = sorted(RUNS_DIR.glob(pat))
    if not cands:
        return None
    g = json.loads(cands[-1].read_text())
    return g, cands[-1]


def resolve_session_path(p: str) -> Path:
    if not p:
        return Path("/dev/null")
    cands: list[Path] = []
    if p.startswith("/app/"):
        cands.append(M4 / p[len("/app/"):])
        cands.append(ROOT / p[len("/app/"):])
    elif p.startswith("/"):
        cands.append(Path(p))
    else:
        cands.append(M4 / p)
    base = Path(p).name
    cands.append(LOGS_DIR / base)
    for c in cands:
        if c.exists():
            return c
    return cands[0]


def build_session_index_for_run(run_id: str) -> dict[int, Path]:
    """Index logs that belong to this run_id only (faster than scanning all 24k)."""
    idx: dict[int, Path] = {}
    for p in LOGS_DIR.iterdir():
        if not p.name.startswith("session_") or p.suffix != ".jsonl":
            continue
        ev = read_first_event(p)
        if not ev or ev.get("event") != "session_start" or ev.get("run_id") != run_id:
            continue
        si = ev.get("stage_index")
        if si is not None and int(si) not in idx:
            idx[int(si)] = p
    return idx


def analyse_session(sp: Path) -> dict:
    try:
        events = parse_concatenated_json(sp.read_text())
    except (OSError, json.JSONDecodeError) as e:
        return {"exec_status": "parse_error", "error": str(e)}
    calls = [e for e in events if e.get("event") == "tool_call"]
    results = [e for e in events if e.get("event") == "tool_result"]
    if not calls and not results:
        return {"exec_status": "no_tool_calls", "n_tool_calls": 0,
                "n_tool_results": 0, "n_tool_results_failed": 0,
                "tool_call_summary": [], "write_file_paths_ok": [], "failed_calls": []}
    failed = [r for r in results if r.get("success") is not True]
    if failed:
        status = "tool_failed"
    elif not results:
        status = "no_tool_results"
    else:
        status = "passed"

    # Pair tool_call → next tool_result of the same `tool` name in the seq stream.
    by_seq = sorted([e for e in events if e.get("event") in ("tool_call", "tool_result")],
                    key=lambda e: e.get("seq") or 0)
    tcs, write_ok, failed_summ = [], [], []
    pending_calls: list[dict] = []
    for e in by_seq:
        if e.get("event") == "tool_call":
            pending_calls.append(e)
        else:  # tool_result
            tool = e.get("tool")
            # find earliest pending call with the same tool
            match_idx = next((i for i, c in enumerate(pending_calls) if c.get("tool") == tool), None)
            if match_idx is None:
                continue
            c = pending_calls.pop(match_idx)
            succ = e.get("success")
            path = None
            try:
                args = json.loads(c.get("arguments") or "{}")
                path = args.get("path") or args.get("file_path") or args.get("filename")
            except json.JSONDecodeError:
                pass
            tcs.append({"tool": tool, "path": path, "success": succ})
            if tool in ("write_file", "append_file", "edit_file") and succ is True and path:
                write_ok.append(path)
            if succ is not True:
                failed_summ.append({"tool": tool, "path": path,
                                    "result_preview": trunc(e.get("result_preview"), 300)})
    return {
        "exec_status": status,
        "n_tool_calls": len(calls),
        "n_tool_results": len(results),
        "n_tool_results_failed": len(failed),
        "tool_call_summary": tcs,
        "write_file_paths_ok": write_ok,
        "failed_calls": failed_summ,
    }


def main():
    src = json.loads(INPUT_FILE.read_text())
    print(f"input file: {INPUT_FILE}", file=sys.stderr)
    print(f"  campaign={src['campaign']}  num_variations={src['num_variations']}", file=sys.stderr)

    var = next((v for v in src["variations"] if v["seed"] == TARGET_SEED), None)
    if not var:
        sys.exit(f"no variation with seed={TARGET_SEED}")
    print(f"  variation: campaign_id={var['campaign_id']} seed={var['seed']} total_fragments={var['total_fragments']}", file=sys.stderr)

    found = find_graph_for_seed(TARGET_SEED, src["campaign"])
    if not found:
        sys.exit("no malicious4 run for this campaign/seed")
    g, g_path = found
    v = g.get("variation") or {}
    run_id = g.get("run_id")
    g_frags = {f.get("fragment_index"): f for f in (v.get("fragments") or [])}
    print(f"  graph: {g_path.name}  run_id={run_id}  fragments_in_graph={len(g_frags)}", file=sys.stderr)

    out_records = []
    for frag_in in var["fragments"][:N_FRAGMENTS]:
        idx = frag_in["fragment_index"]
        g_frag = g_frags.get(idx)
        prompt_direct = next((v["prompt"] for v in frag_in.get("variations", [])
                              if v.get("style") == "direct"), None)

        rec = {
            "fragment_index": idx,
            "parent_tactic": frag_in.get("parent_tactic"),
            "parent_prompt": trunc(frag_in.get("parent_prompt"), 250),
            "direct_prompt": trunc(prompt_direct, 250),
        }
        if not g_frag:
            rec["status"] = "NO_GRAPH_ENTRY"
            out_records.append(rec)
            continue

        rec["produces"] = g_frag.get("produces") or []
        rec["consumes"] = g_frag.get("consumes") or []
        rec["judge_passed"] = g_frag.get("passed")
        rec["judge_verdict"] = g_frag.get("verdict")
        rec["judge_justification"] = trunc(g_frag.get("justification"), 250)

        sp = resolve_session_path(g_frag.get("session_path") or "")
        if not sp.exists():
            rec["exec_status"] = "session_missing"
            rec["session_path"] = str(sp)
            out_records.append(rec)
            continue

        an = analyse_session(sp)
        rec["session_path"] = str(sp)
        rec.update(an)
        rec["produced_via_write_file"] = bool(an["write_file_paths_ok"])
        out_records.append(rec)

    output = {
        "input_file": str(INPUT_FILE),
        "variation": {"campaign_id": var["campaign_id"], "seed": var["seed"]},
        "graph_file": g_path.name,
        "run_id": run_id,
        "fragments_tested": out_records,
    }
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
