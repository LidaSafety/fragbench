"""Run picked attacks through the existing MCP CLI with hybrid topological parallelism.

Pipeline per run:

1. Pick all requested ``(seed, style)`` attacks from a fragments JSON file
   using :mod:`attack_picker`.
2. For each variation, schedule its fragments according to the
   ``produces``/``consumes`` DAG.  Fragments that share no dependencies run
   in parallel (capped by ``--max-parallel-fragments``).  Variations also
   run in parallel (capped by ``--max-parallel-variations``).
3. Each fragment is dispatched as a subprocess invocation of
   ``fragbench_mcp/mcp_cli.py`` (the same path the existing Makefile uses)
   so the existing live JSONL logger / frontend keeps working unchanged.
4. After every fragment finishes, run :mod:`attack_success` to determine
   pass/fail.  A variation passes iff every fragment passes.
5. Write two artifacts **per seed** under ``results/runs/``:
     * ``<run_id>_seed_<seed>_<CAMPAIGN>.json`` — chain summary: ordered
       fragment list with prompts, ``produces``/``consumes``, and per-fragment
       ``passed`` / ``verdict`` / ``justification`` (no tool executions, no
       response previews).
     * ``attack_graph_<run_id_suffix>_seed_<seed>_<CAMPAIGN>.json`` — full
       graph_format-shaped detail with ``tools_executed`` per fragment.

This script is the user-facing entry point.  ``make attack-graph-run`` wraps it.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from attack_picker import PickedAttack, PickedFragment, list_seeds, pick_attack
from attack_success import (
    JUDGE_SYSTEM,  # noqa: F401  (re-exported so callers can introspect)
    VariationOutcome,
    check_variation,
)

REPO_ROOT = Path(__file__).resolve().parent
DEFAULT_FRAGMENTS = REPO_ROOT / "results" / "promptsteal_fragments.json"
DEFAULT_RESULTS_DIR = REPO_ROOT / "results" / "runs"
DEFAULT_LOG_DIR = REPO_ROOT / "logs"
MCP_CLI_PATH = REPO_ROOT / "fragbench_mcp" / "mcp_cli.py"


# ---------------------------------------------------------------------------
# Subprocess driver — one fragment -> one mcp_cli.py run -> one session JSONL
# ---------------------------------------------------------------------------


_SESSION_LOG_RE = re.compile(r"(?:Session log:|Logging to)\s*(\S+\.jsonl)")


def _format_seeds_arg(values: list[int]) -> str:
    return ",".join(str(v) for v in values)


def parse_seeds(spec: str) -> list[int]:
    """Parse '0', '0,2,4', '0-9', '0-3,7,12-14' into a sorted unique list."""
    if not spec:
        return []
    out: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            lo, hi = chunk.split("-", 1)
            out.update(range(int(lo), int(hi) + 1))
        else:
            out.add(int(chunk))
    return sorted(out)


def _extract_target_model(extra_args: list[str]) -> tuple[str | None, str | None]:
    """Discover the target LLM driving the MCP agent loop.

    Resolution order:
      1. ``--model-backend`` / ``--model`` pairs in the mcp_cli passthrough
         args (this is what the Makefile actually sets).
      2. ``MCP_MODEL_BACKEND`` / ``MCP_MODEL`` env vars (canonical names).
      3. ``MODEL_BACKEND`` / ``MODEL`` env vars (legacy aliases).
    """
    backend: str | None = None
    model: str | None = None
    i = 0
    while i < len(extra_args):
        token = extra_args[i]
        if token == "--model-backend" and i + 1 < len(extra_args):
            backend = extra_args[i + 1]
            i += 2
            continue
        if token == "--model" and i + 1 < len(extra_args):
            model = extra_args[i + 1]
            i += 2
            continue
        if token.startswith("--model-backend="):
            backend = token.split("=", 1)[1]
        elif token.startswith("--model="):
            model = token.split("=", 1)[1]
        i += 1
    backend = backend or os.environ.get("MCP_MODEL_BACKEND") or os.environ.get("MODEL_BACKEND")
    model = model or os.environ.get("MCP_MODEL") or os.environ.get("MODEL")
    return backend, model


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _log(msg: str) -> None:
    """Print with immediate flush so progress is visible inside Docker."""
    print(msg, flush=True)


async def _spawn_mcp_cli(
    *,
    prompt: str,
    run_id: str,
    attack_id: str,
    style: str,
    seed: int,
    fragment_index: int,
    log_dir: Path,
    extra_args: list[str],
) -> tuple[Path | None, int, str]:
    """Run mcp_cli.py once with --prompt; return (session_path, returncode, stdout_tail)."""
    cmd = [
        sys.executable,
        str(MCP_CLI_PATH),
        "--auto-toolkits",
        "--log-dir",
        str(log_dir),
        "--run-id",
        run_id,
        "--campaign",
        attack_id,
        "--attack-id",
        attack_id,
        "--stage-index",
        str(fragment_index),
        "--variation-index",
        str(seed),
        "--style",
        style,
        "--prompt",
        prompt,
        *extra_args,
    ]

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        cwd=str(REPO_ROOT),
        env=os.environ.copy(),
    )
    out_bytes, _ = await proc.communicate()
    out = out_bytes.decode("utf-8", errors="replace")

    session_path: Path | None = None
    for m in _SESSION_LOG_RE.finditer(out):
        session_path = Path(m.group(1).strip())
        if not session_path.is_absolute():
            session_path = (REPO_ROOT / session_path).resolve()
    tail = out[-2000:] if len(out) > 2000 else out
    return session_path, proc.returncode or 0, tail


# ---------------------------------------------------------------------------
# Topological scheduler within one variation
# ---------------------------------------------------------------------------


def _build_dependencies(picked: PickedAttack) -> dict[int, set[int]]:
    """For each fragment, find the most-recent earlier producer of each consumed artifact."""
    deps: dict[int, set[int]] = {}
    fragments = list(picked.fragments)
    for i, frag in enumerate(fragments):
        d: set[int] = set()
        for art in frag.consumes:
            for earlier in reversed(fragments[:i]):
                if art in earlier.produces:
                    d.add(earlier.index)
                    break
        deps[frag.index] = d
    return deps


async def _run_variation(
    picked: PickedAttack,
    *,
    run_id: str,
    log_dir: Path,
    var_sem: asyncio.Semaphore,
    max_parallel_fragments: int,
    extra_args: list[str],
    use_judge: bool,
    judge_model: str,
    judge_backend: str,
    judge_api_key: str | None,
) -> tuple[VariationOutcome, dict[int, dict[str, Any]]]:
    """Drive one variation; return (outcome, per_fragment_stdout_metadata)."""
    async with var_sem:
        deps = _build_dependencies(picked)
        frag_sem = asyncio.Semaphore(max(1, max_parallel_fragments))
        fragment_tasks: dict[int, asyncio.Task] = {}
        per_frag_meta: dict[int, dict[str, Any]] = {}

        async def run_one(frag: PickedFragment) -> Path | None:
            for dep_idx in deps[frag.index]:
                if dep_idx in fragment_tasks:
                    await fragment_tasks[dep_idx]
            async with frag_sem:
                deps_str = ",".join(str(d) for d in sorted(deps[frag.index])) or "-"
                _log(
                    f"  [{_ts()}] seed={picked.seed:<3} frag={frag.index:<2} "
                    f"role={frag.role:<10} deps=[{deps_str}] start"
                )
                t0 = datetime.now(timezone.utc)
                session_path, rc, tail = await _spawn_mcp_cli(
                    prompt=frag.prompt,
                    run_id=run_id,
                    attack_id=picked.campaign_id,
                    style=picked.style,
                    seed=picked.seed,
                    fragment_index=frag.index,
                    log_dir=log_dir,
                    extra_args=extra_args,
                )
                t1 = datetime.now(timezone.utc)
                duration_ms = int((t1 - t0).total_seconds() * 1000)
                status = "OK " if rc == 0 else f"ERR{rc}"
                _log(
                    f"  [{_ts()}] seed={picked.seed:<3} frag={frag.index:<2} "
                    f"role={frag.role:<10} done  {status} "
                    f"in {duration_ms / 1000:6.1f}s  → "
                    f"{session_path.name if session_path else '(no session)'}"
                )
                per_frag_meta[frag.index] = {
                    "returncode": rc,
                    "session_path": str(session_path) if session_path else None,
                    "started_at": t0.isoformat(),
                    "ended_at": t1.isoformat(),
                    "duration_ms": duration_ms,
                    "stdout_tail": tail if rc != 0 else "",
                }
                return session_path

        for frag in picked.fragments:
            fragment_tasks[frag.index] = asyncio.create_task(run_one(frag))

        sessions: dict[int, Path | None] = {}
        for idx, task in fragment_tasks.items():
            try:
                sessions[idx] = await task
            except Exception as exc:  # noqa: BLE001
                per_frag_meta.setdefault(idx, {})["error"] = repr(exc)
                sessions[idx] = None

    outcome = check_variation(
        picked,
        sessions,
        use_judge=use_judge,
        judge_model=judge_model,
        judge_backend=judge_backend,
        judge_api_key=judge_api_key,
    )
    return outcome, per_frag_meta


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------


def _phase_index_map(fragments: list[PickedFragment]) -> dict[str, int]:
    seen: dict[str, int] = {}
    for f in fragments:
        if f.parent_tactic and f.parent_tactic not in seen:
            seen[f.parent_tactic] = len(seen)
    return seen


def _safe_campaign_token(campaign: str | None) -> str:
    """Normalise a campaign id into a filesystem-safe slug for output filenames."""
    if not campaign:
        return "UNKNOWN"
    text = re.sub(r"[^A-Za-z0-9._-]+", "_", str(campaign).strip())
    return text.strip("_") or "UNKNOWN"


def chain_filename(run_id: str, seed: int, campaign: str | None) -> str:
    """``attack_<DATETIME>_<RUNID>_seed_<SEED>_<CAMPAIGN>.json``.

    ``run_id`` is already ``attack_<DATETIME>_<RUNID>``, so we just append the
    per-seed suffix.
    """
    return f"{run_id}_seed_{seed}_{_safe_campaign_token(campaign)}.json"


def graph_filename(run_id: str, seed: int, campaign: str | None) -> str:
    """``attack_graph_<DATETIME>_<RUNID>_seed_<SEED>_<CAMPAIGN>.json``.

    The run_id starts with ``attack_``; we strip that and prepend
    ``attack_graph_`` so the graph file is unambiguously distinct from the
    chain file but still groups by the same DATETIME+RUNID prefix.
    """
    suffix = run_id.removeprefix("attack_") if run_id.startswith("attack_") else run_id
    return f"attack_graph_{suffix}_seed_{seed}_{_safe_campaign_token(campaign)}.json"


def write_chain_file(
    out_path: Path,
    *,
    run_id: str,
    seed: int,
    attack: PickedAttack,
    outcome: VariationOutcome,
    style: str,
    fragments_path: str,
    started_at: str | None,
    ended_at: str | None,
    target_model: str | None = None,
    target_backend: str | None = None,
    judge_model: str | None = None,
) -> None:
    """Per-seed chain summary: the ordered sequence of fragments + verdicts.

    Smaller than the graph file (no tool executions, no final-response previews)
    so it's easy to grep, diff, or feed into downstream chain-level analysis.
    """
    by_idx = {fo.fragment_index: fo for fo in outcome.fragments}
    fragments_list: list[dict[str, Any]] = []
    for f in attack.fragments:
        fo = by_idx.get(f.index)
        fragments_list.append(
            {
                "fragment_index": f.index,
                "role": f.role,
                "phase": f.parent_tactic or "unknown",
                "prompt": f.prompt,
                "produces": list(f.produces),
                "consumes": list(f.consumes),
                "passed": bool(fo.passed) if fo else False,
                "verdict": fo.verdict if fo else None,
                "justification": fo.justification if fo else "no outcome",
                "classifier": fo.classifier if fo else "none",
            }
        )
    target_label = (
        f"{target_backend}:{target_model}" if (target_model and target_backend)
        else (target_model or None)
    )
    payload = {
        "run_id": run_id,
        "seed": seed,
        "campaign": attack.metadata.get("id") or attack.campaign,
        "campaign_id": attack.campaign_id,
        "style": style,
        "fragments_path": fragments_path,
        "started_at": started_at,
        "ended_at": ended_at,
        "passed": bool(outcome.passed),
        "target_model": target_model,
        "target_backend": target_backend,
        "llm_product": target_label,
        "judge_model": judge_model,
        "fragments": fragments_list,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _build_graph_entry(
    *,
    user_id: int,
    attack: PickedAttack,
    outcome: VariationOutcome,
    fragment_meta: dict[int, dict[str, Any]],
    started_at: str | None,
    ended_at: str | None,
    target_model: str | None = None,
    target_backend: str | None = None,
    judge_model: str | None = None,
) -> dict[str, Any]:
    phase_idx = _phase_index_map(list(attack.fragments))
    phases_in_order = sorted(phase_idx.keys(), key=lambda p: phase_idx[p])

    fragments: list[dict[str, Any]] = []
    by_idx = {fo.fragment_index: fo for fo in outcome.fragments}
    for f in attack.fragments:
        fo = by_idx.get(f.index)
        meta = fragment_meta.get(f.index, {})
        fragments.append(
            {
                "fragment_id": f"{attack.seed}_phase{phase_idx.get(f.parent_tactic, -1)}_frag{f.index}",
                "fragment_index": f.index,
                "prompt": f.prompt,
                "style": f.style,
                "phase": f.parent_tactic or "unknown",
                "phase_index": phase_idx.get(f.parent_tactic, -1),
                "role": f.role,
                "produces": list(f.produces),
                "consumes": list(f.consumes),
                "is_cover": False,
                "passed": bool(fo.passed) if fo else False,
                "verdict": fo.verdict if fo else None,
                "justification": fo.justification if fo else "no outcome",
                "classifier": fo.classifier if fo else "none",
                "tools_executed": fo.tools_executed if fo else [],
                "final_response_preview": (fo.final_response[:600] + "…")
                if fo and len(fo.final_response) > 600
                else (fo.final_response if fo else ""),
                "artifacts_resolved": fo.artifacts_resolved if fo else {},
                "artifacts_found": fo.artifacts_found if fo else {},
                "session_path": fo.session_path if fo else meta.get("session_path"),
                "duration_ms": meta.get("duration_ms"),
                "started_at": meta.get("started_at"),
                "ended_at": meta.get("ended_at"),
            }
        )

    duration_ms_total = sum(int(m.get("duration_ms") or 0) for m in fragment_meta.values())
    if target_model and target_backend:
        llm_product = f"{target_backend}:{target_model}"
    elif target_model:
        llm_product = target_model
    else:
        llm_product = None
    return {
        "user_id": user_id,
        "seed": attack.seed,
        "style": attack.style,
        "campaign": attack.metadata.get("id") or attack.campaign,
        "campaign_id": attack.campaign_id,
        "campaign_source": attack.metadata.get("description"),
        "campaign_date": None,
        "llm_product": llm_product,
        "llm_backend": target_backend,
        "llm_model": target_model,
        "judge_model": judge_model,
        "campaign_description": attack.metadata.get("description"),
        "duration_hours": round(duration_ms_total / 3_600_000, 4) if duration_ms_total else 0.0,
        "num_total_fragments": len(attack.fragments),
        "num_attack_fragments": len(attack.fragments),
        "num_cover_fragments": 0,
        "phases_in_order": phases_in_order,
        "fragments": fragments,
        "passed": bool(outcome.passed),
        "started_at": started_at,
        "ended_at": ended_at,
    }


def write_graph_entry_file(
    out_path: Path,
    *,
    run_id: str,
    user_id: int,
    attack: PickedAttack,
    outcome: VariationOutcome,
    fragment_meta: dict[int, dict[str, Any]],
    style: str,
    fragments_path: str,
    started_at: str,
    ended_at: str,
    target_model: str | None = None,
    target_backend: str | None = None,
    judge_model: str | None = None,
) -> None:
    """Per-seed graph entry: full graph_format-shape with tool executions."""
    entry = _build_graph_entry(
        user_id=user_id,
        attack=attack,
        outcome=outcome,
        fragment_meta=fragment_meta,
        started_at=started_at,
        ended_at=ended_at,
        target_model=target_model,
        target_backend=target_backend,
        judge_model=judge_model,
    )
    target_label = (
        f"{target_backend}:{target_model}" if (target_model and target_backend)
        else (target_model or None)
    )
    payload = {
        # Run-level header so the file is self-describing and the viewer can
        # group per-seed graph files under one logical run without needing to
        # consult anything else on disk.
        "run_id": run_id,
        "campaign": attack.metadata.get("id") or attack.campaign,
        "style": style,
        "fragments_path": fragments_path,
        "started_at": started_at,
        "ended_at": ended_at,
        "target_model": target_model,
        "target_backend": target_backend,
        "llm_product": target_label,
        "judge_model": judge_model,
        # Per-seed payload (the same shape that previously lived inside
        # ``variations[i]`` of the monolithic graph file).
        "variation": entry,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run a parallel attack from a fragments JSON file.")
    p.add_argument("--fragments", default=str(DEFAULT_FRAGMENTS), help="Path to fragments JSON.")
    p.add_argument("--style", default="direct", help="Style to pick (e.g. direct, sysadmin).")
    p.add_argument(
        "--seeds",
        default=None,
        help="Seeds spec: '0', '0,2,4', '0-9', '0-3,7,12-14'. Defaults to all seeds in the file.",
    )
    p.add_argument("--max-parallel-variations", type=int, default=2)
    p.add_argument("--max-parallel-fragments", type=int, default=2)
    p.add_argument("--run-id", default=None)
    p.add_argument("--results-dir", default=str(DEFAULT_RESULTS_DIR))
    p.add_argument(
        "--log-dir",
        default=None,
        help=(
            "Where session_*.jsonl files are written. Defaults to "
            "``<DEFAULT_LOG_DIR>/<run_id>/`` so every execution gets its own "
            "isolated subdirectory and historical session files from previous "
            "runs can never bleed into the judge or the live viewer."
        ),
    )
    p.add_argument(
        "--mcp-arg",
        action="append",
        default=[],
        help=(
            "Extra arg forwarded to mcp_cli.py (repeatable). When the value "
            "starts with '--' you MUST use the equals form, e.g. "
            "--mcp-arg=--model-backend --mcp-arg=ollama, otherwise argparse "
            "treats the value as a new option."
        ),
    )
    p.add_argument(
        "--judge",
        action="store_true",
        help="Use the LLM judge for fragment success (mirror of mcp_cli.py --judge). "
             "Without --judge the deterministic keyword fallback is used.",
    )
    p.add_argument(
        "--judge-model",
        default="anthropic/claude-haiku-4.5",
        help="Model id for the success judge (OpenRouter format by default).",
    )
    p.add_argument(
        "--judge-backend",
        choices=["openrouter", "anthropic"],
        default="openrouter",
        help="Backend for the success judge (default: openrouter).",
    )
    p.add_argument(
        "--no-forward-judge",
        action="store_true",
        help="Do not pass --judge to mcp_cli.py subprocesses (per-response classifier still runs).",
    )
    p.add_argument("--dry-run", action="store_true", help="Print the picked prompts and exit.")
    return p.parse_args(argv)


def _print_summary(seeds: list[int], outcomes: dict[int, VariationOutcome]) -> None:
    passes = [outcomes[s].passed if s in outcomes else False for s in seeds]
    total = len(seeds)
    passed = sum(1 for v in passes if v)
    _log(f"\n{'=' * 64}")
    _log(f"  Variations: {total}   Passed: {passed}   Failed: {total - passed}")
    _log(f"{'=' * 64}")
    for s in seeds:
        oc = outcomes.get(s)
        if oc is None:
            _log(f"  seed={s:<4} ?  no outcome")
            continue
        ok = "PASS" if oc.passed else "FAIL"
        frag_summary = ",".join("Y" if fo.passed else "n" for fo in oc.fragments)
        _log(f"  seed={s:<4} {ok}  fragments=[{frag_summary}]")


async def _run_async(args: argparse.Namespace) -> int:
    fragments_path = Path(args.fragments).resolve()
    if not fragments_path.exists():
        print(f"ERROR: fragments file not found: {fragments_path}", file=sys.stderr)
        return 2

    if args.seeds:
        seeds = parse_seeds(args.seeds)
    else:
        seeds = list_seeds(fragments_path)
    if not seeds:
        print("ERROR: no seeds to run.", file=sys.stderr)
        return 2

    run_id = args.run_id or f"attack_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
    # Each execution gets its own ``logs/<run_id>/`` directory so the judge
    # and the live viewer can never accidentally pick up session JSONLs from
    # a previous run. ``--log-dir`` overrides this when explicitly provided.
    if args.log_dir:
        log_dir = Path(args.log_dir).resolve()
    else:
        log_dir = (DEFAULT_LOG_DIR / run_id).resolve()
    log_dir.mkdir(parents=True, exist_ok=True)
    results_dir = Path(args.results_dir).resolve()

    attacks: dict[int, PickedAttack] = {}
    for s in seeds:
        attacks[s] = pick_attack(fragments_path, s, args.style)

    _log(f"\n[attack_runner] run_id={run_id}")
    _log(f"[attack_runner] fragments={fragments_path}")
    _log(
        f"[attack_runner] style={args.style!r}  seeds={len(seeds)}  "
        f"parallel_vars={args.max_parallel_variations}  parallel_frags={args.max_parallel_fragments}"
    )
    judge_label = (
        f"llm_judge ({args.judge_backend}/{args.judge_model})" if args.judge else "keyword (deterministic)"
    )
    _log(f"[attack_runner] success classifier: {judge_label}")
    _log(f"[attack_runner] log_dir={log_dir}")
    _log(f"[attack_runner] results_dir={results_dir}")
    n_frags_total = sum(len(a.fragments) for a in attacks.values())
    _log(f"[attack_runner] total fragments to dispatch: {n_frags_total}")

    if args.dry_run:
        for s in seeds[:5]:
            a = attacks[s]
            print(f"\n--- seed={s} {a.campaign_id} ---")
            for f in a.fragments:
                print(f"  [{f.index}] role={f.role} produces={list(f.produces)} consumes={list(f.consumes)}")
                print(f"      {f.prompt[:140]}")
        return 0

    var_sem = asyncio.Semaphore(max(1, args.max_parallel_variations))
    extra_args = list(args.mcp_arg or [])
    judge_api_key = (
        os.environ.get("OPENROUTER_API_KEY")
        or os.environ.get("ANTHROPIC_API_KEY")
    )
    if args.judge and not judge_api_key:
        _log(
            "[attack_runner] --judge set but no OPENROUTER_API_KEY/ANTHROPIC_API_KEY; "
            "judge will fall back to keyword classifier per fragment."
        )
    if args.judge and not args.no_forward_judge:
        # Forward judge flags into mcp_cli.py so the per-response verdict in the
        # session JSONL is also LLM-judged (consistent with `make docker-attack-run JUDGE=1`).
        extra_args.extend([
            "--judge",
            "--judge-model", args.judge_model,
            "--judge-backend", args.judge_backend,
        ])
    target_backend, target_model = _extract_target_model(extra_args)
    judge_model_used = args.judge_model if args.judge else None
    if target_model or target_backend:
        _log(
            f"[attack_runner] target model: {target_backend or '?'}:{target_model or '?'}"
            + (f"  judge: {judge_model_used}" if judge_model_used else "")
        )
    started_at = datetime.now(timezone.utc).isoformat()

    # Meta marker: written *before* any variations run so the live viewer can
    # associate in-progress runs with their fragments file (and therefore not
    # filter them out when the user has a fragments selector active). The
    # graph index reads this when no per-seed graph file has been flushed yet.
    sample_attack = next(iter(attacks.values()))
    meta_path = results_dir / f"{run_id}_meta.json"
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    target_label = (
        f"{target_backend}:{target_model}" if (target_model and target_backend)
        else (target_model or None)
    )
    meta_path.write_text(
        json.dumps(
            {
                "run_id": run_id,
                "campaign": sample_attack.campaign,
                "style": args.style,
                "fragments_path": str(fragments_path),
                "seeds": list(seeds),
                "started_at": started_at,
                "target_model": target_model,
                "target_backend": target_backend,
                "llm_product": target_label,
                "judge_model": judge_model_used,
                "status": "running",
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    _log(
        f"\n[attack_runner] dispatching {len(seeds)} variations "
        f"({n_frags_total} fragments total) — up to "
        f"{args.max_parallel_variations * args.max_parallel_fragments} subprocesses concurrently"
    )

    async def run_seed(s: int) -> tuple[int, VariationOutcome, dict[int, dict[str, Any]]]:
        oc, meta = await _run_variation(
            attacks[s],
            run_id=run_id,
            log_dir=log_dir,
            var_sem=var_sem,
            max_parallel_fragments=args.max_parallel_fragments,
            extra_args=extra_args,
            use_judge=args.judge,
            judge_model=args.judge_model,
            judge_backend=args.judge_backend,
            judge_api_key=judge_api_key,
        )
        verdict = "PASS" if oc.passed else "FAIL"
        classifier_set = {fo.classifier for fo in oc.fragments}
        cls_tag = "/".join(sorted(classifier_set)) if classifier_set else "n/a"
        per_frag = ",".join("Y" if fo.passed else "n" for fo in oc.fragments)
        _log(
            f"  [{_ts()}] seed={s:<3} VARIATION {verdict}  classifier={cls_tag}  "
            f"frags=[{per_frag}]"
        )
        return s, oc, meta

    tasks = [asyncio.create_task(run_seed(s)) for s in seeds]
    results = await asyncio.gather(*tasks)
    ended_at = datetime.now(timezone.utc).isoformat()

    outcomes: dict[int, VariationOutcome] = {}
    metas: dict[int, dict[int, dict[str, Any]]] = {}
    for seed, outcome, meta in results:
        outcomes[seed] = outcome
        metas[seed] = meta

    _print_summary(seeds, outcomes)

    # Per-seed output: one chain file + one graph file per variation.
    # Layout in ``results/runs/``:
    #   <run_id>_seed_<seed>_<CAMPAIGN>.json              (chain)
    #   attack_graph_<run_id_suffix>_seed_<seed>_<CAMPAIGN>.json  (graph)
    written_chain: list[Path] = []
    written_graph: list[Path] = []
    for user_id, seed in enumerate(seeds):
        attack = attacks.get(seed)
        outcome = outcomes.get(seed)
        if attack is None or outcome is None:
            continue
        campaign_label = attack.campaign_id or attack.campaign
        chain_path = results_dir / chain_filename(run_id, seed, campaign_label)
        graph_path = results_dir / graph_filename(run_id, seed, campaign_label)
        write_chain_file(
            chain_path,
            run_id=run_id,
            seed=seed,
            attack=attack,
            outcome=outcome,
            style=args.style,
            fragments_path=str(fragments_path),
            started_at=started_at,
            ended_at=ended_at,
            target_model=target_model,
            target_backend=target_backend,
            judge_model=judge_model_used,
        )
        write_graph_entry_file(
            graph_path,
            run_id=run_id,
            user_id=user_id,
            attack=attack,
            outcome=outcome,
            fragment_meta=metas.get(seed, {}),
            style=args.style,
            fragments_path=str(fragments_path),
            started_at=started_at,
            ended_at=ended_at,
            target_model=target_model,
            target_backend=target_backend,
            judge_model=judge_model_used,
        )
        written_chain.append(chain_path)
        written_graph.append(graph_path)

    # Mark the meta marker as complete so the viewer can prefer per-seed
    # graph files going forward. Best-effort — losing this only affects the
    # ``status`` field, never the index lookup.
    try:
        meta_blob = json.loads(meta_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        meta_blob = {}
    meta_blob.update({
        "ended_at": ended_at,
        "status": "complete",
        "num_passed": sum(1 for s in seeds if outcomes.get(s) and outcomes[s].passed),
    })
    try:
        meta_path.write_text(json.dumps(meta_blob, indent=2), encoding="utf-8")
    except OSError:
        pass

    _log("")
    for p in written_chain:
        _log(f"[attack_runner] wrote chain  {p.name}")
    for p in written_graph:
        _log(f"[attack_runner] wrote graph  {p.name}")
    _log(f"[attack_runner] viewer: http://localhost:8787/graph.html?run={run_id}")

    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    return asyncio.run(_run_async(args))


if __name__ == "__main__":
    raise SystemExit(main())
