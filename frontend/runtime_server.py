#!/usr/bin/env python3
"""Runtime-backed FragGuard viewer server.

Serves the modular frontend from ``frontend/`` and provides API endpoints that
normalize runtime artifacts (seeds, attack TOML, session JSONL, MCP logs) into
a single viewer payload.
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterable

try:
    import tomllib  # type: ignore[attr-defined]
except ModuleNotFoundError:  # pragma: no cover - py<3.11 fallback
    tomllib = None


REPO_ROOT = Path(__file__).resolve().parent.parent
FRONTEND_ROOT = REPO_ROOT / "frontend"
LOGS_DIR = REPO_ROOT / "logs"
SEEDS_DIR = REPO_ROOT / "seeds"
ATTACKS_DIR = REPO_ROOT / "attacks"
MCP_LOGS_DIR = REPO_ROOT / "mcp" / "logs"
RESULTS_RUNS_DIR = REPO_ROOT / "results" / "runs"


# Output file naming (per-seed):
#   chain : ``<run_id>_seed_<seed>_<CAMPAIGN>.json``                where run_id starts with ``attack_``
#   graph : ``attack_graph_<run_id_minus_attack_prefix>_seed_<seed>_<CAMPAIGN>.json``
#
# Legacy (single file per run) naming we still understand for back-compat:
#   ``<run_id>_passes.json``
#   ``<run_id>_graph.json``
_CHAIN_FILE_RE = re.compile(
    r"^(?P<run_id>attack_(?!graph_)[A-Za-z0-9._-]+?)_seed_(?P<seed>-?\d+)_(?P<campaign>[A-Za-z0-9._-]+)\.json$"
)
_GRAPH_FILE_RE = re.compile(
    r"^attack_graph_(?P<runid_suffix>[A-Za-z0-9._-]+?)_seed_(?P<seed>-?\d+)_(?P<campaign>[A-Za-z0-9._-]+)\.json$"
)


def _parse_chain_filename(p: Path) -> tuple[str, int, str] | None:
    m = _CHAIN_FILE_RE.match(p.name)
    if not m:
        return None
    try:
        return m.group("run_id"), int(m.group("seed")), m.group("campaign")
    except (ValueError, TypeError):
        return None


def _parse_graph_filename(p: Path) -> tuple[str, int, str] | None:
    m = _GRAPH_FILE_RE.match(p.name)
    if not m:
        return None
    try:
        return f"attack_{m.group('runid_suffix')}", int(m.group("seed")), m.group("campaign")
    except (ValueError, TypeError):
        return None


def _list_chain_files() -> list[Path]:
    if not RESULTS_RUNS_DIR.exists():
        return []
    return [p for p in RESULTS_RUNS_DIR.glob("*.json") if _parse_chain_filename(p) is not None]


def _list_graph_files() -> list[Path]:
    if not RESULTS_RUNS_DIR.exists():
        return []
    return [p for p in RESULTS_RUNS_DIR.glob("attack_graph_*.json") if _parse_graph_filename(p) is not None]


def _chain_files_for_run(run_id: str) -> list[Path]:
    return [p for p in _list_chain_files() if (parsed := _parse_chain_filename(p)) and parsed[0] == run_id]


def _graph_files_for_run(run_id: str) -> list[Path]:
    return [p for p in _list_graph_files() if (parsed := _parse_graph_filename(p)) and parsed[0] == run_id]


@dataclass(frozen=True)
class ArtifactBundle:
    """Canonical runtime artifact container before normalization."""

    seeds: list[dict[str, Any]]
    attacks: list[dict[str, Any]]
    session_events: list[dict[str, Any]]
    mcp_logs: list[dict[str, Any]]
    source: dict[str, Any]


def _safe_json_loads(line: str) -> dict[str, Any] | None:
    try:
        value = json.loads(line)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    if not path.exists():
        return events
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parsed = _safe_json_loads(line)
        if parsed is not None:
            events.append(parsed)
    return events


def load_seeds(seed_paths: Iterable[Path] | None = None) -> list[dict[str, Any]]:
    paths = sorted(seed_paths) if seed_paths else sorted(SEEDS_DIR.glob("*.json"))
    out: list[dict[str, Any]] = []
    for path in paths:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if isinstance(payload, dict):
            payload["_source_file"] = path.name
            out.append(payload)
    return out


def load_attack_toml(attack_paths: Iterable[Path] | None = None) -> list[dict[str, Any]]:
    paths = sorted(attack_paths) if attack_paths else sorted(ATTACKS_DIR.glob("*.toml"))
    out: list[dict[str, Any]] = []
    for path in paths:
        text = path.read_text(encoding="utf-8")
        payload: dict[str, Any] | None = None
        if tomllib is not None:
            try:
                payload = tomllib.loads(text)
            except (tomllib.TOMLDecodeError, OSError):
                payload = None
        else:
            payload = parse_attack_toml_minimal(text)
        if payload is None:
            continue
        if isinstance(payload, dict):
            payload["_source_file"] = path.name
            out.append(payload)
    return out


def parse_attack_toml_minimal(text: str) -> dict[str, Any]:
    """Parse minimal attack TOML shape for Python environments without tomllib."""
    metadata: dict[str, Any] = {}
    fragments: list[dict[str, Any]] = []
    current_fragment: dict[str, Any] | None = None
    current_variation: dict[str, Any] | None = None

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line == "[[fragments]]":
            current_fragment = {"variations": []}
            fragments.append(current_fragment)
            current_variation = None
            continue
        if line == "[[fragments.variations]]":
            if current_fragment is None:
                current_fragment = {"variations": []}
                fragments.append(current_fragment)
            current_variation = {}
            current_fragment["variations"].append(current_variation)
            continue
        if line == "[metadata]":
            current_fragment = None
            current_variation = None
            continue
        if "=" not in line:
            continue
        key, value = [x.strip() for x in line.split("=", 1)]
        value = value.strip().strip('"').strip("'")
        if key in {"id", "technique", "technique_name", "description"} and current_fragment is None and current_variation is None:
            metadata[key] = value
        elif current_variation is not None and key in {"style", "prompt"}:
            current_variation[key] = value
        elif current_fragment is not None and key in {"index", "description"}:
            if key == "index":
                try:
                    current_fragment[key] = int(value)
                except ValueError:
                    current_fragment[key] = 0
            else:
                current_fragment[key] = value

    return {"metadata": metadata, "fragments": fragments}


def list_session_files() -> list[Path]:
    """Return every ``session_*.jsonl`` under ``logs/`` and ``logs/<run_id>/``.

    ``attack_runner`` defaults to writing each execution's session files into
    its own ``logs/<run_id>/`` subdirectory so historical data can never leak
    between runs. Older one-off runs (``mcp_cli.py`` invoked directly) still
    drop their files at the top level — we pick up both.
    """
    return sorted(
        list(LOGS_DIR.glob("session_*.jsonl"))
        + list(LOGS_DIR.glob("*/session_*.jsonl")),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )


def _graph_run_index() -> dict[str, dict[str, Any]]:
    """{run_id -> {fragments_path, mtime, ...}} for every known attack run.

    Sources, in *increasing* authority (later sources overwrite earlier):

    1. ``<run_id>_meta.json`` — written by ``attack_runner`` at run **start**,
       before any per-seed graph file has been flushed. Lets the live viewer
       associate in-progress runs with their fragments file so the fragments
       filter does not silently drop them.
    2. Legacy ``<run_id>_graph.json`` — single-file pre-per-seed runs.
    3. Per-seed ``attack_graph_<...>_seed_<seed>_<CAMPAIGN>.json`` files.
    """
    if not RESULTS_RUNS_DIR.exists():
        return {}
    out: dict[str, dict[str, Any]] = {}

    # 1. Meta markers (in-progress runs and finished runs alike).
    for f in RESULTS_RUNS_DIR.glob("*_meta.json"):
        run_id = f.name[: -len("_meta.json")]
        try:
            payload = json.loads(f.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        out[run_id] = {
            "fragments_path": payload.get("fragments_path"),
            "campaign": payload.get("campaign"),
            "style": payload.get("style"),
            "mtime": f.stat().st_mtime,
            "status": payload.get("status"),
        }

    # 2. Per-seed graph files (preferred when both exist).
    for f in _list_graph_files():
        parsed = _parse_graph_filename(f)
        if parsed is None:
            continue
        run_id, _seed, _campaign = parsed
        try:
            payload = json.loads(f.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        bucket = out.setdefault(
            run_id,
            {
                "fragments_path": payload.get("fragments_path"),
                "campaign": payload.get("campaign"),
                "style": payload.get("style"),
                "mtime": 0.0,
            },
        )
        # Prefer the freshest file's metadata; track the newest mtime across seeds.
        mtime = f.stat().st_mtime
        if mtime > float(bucket.get("mtime") or 0):
            bucket["fragments_path"] = payload.get("fragments_path") or bucket.get("fragments_path")
            bucket["campaign"] = payload.get("campaign") or bucket.get("campaign")
            bucket["style"] = payload.get("style") or bucket.get("style")
            bucket["mtime"] = mtime

    # 3. Legacy layout: one monolithic ``<run_id>_graph.json`` for the whole run.
    for f in RESULTS_RUNS_DIR.glob("*_graph.json"):
        # Skip new-style files (they also match this glob but parse as graph filenames).
        if _parse_graph_filename(f) is not None:
            continue
        run_id = f.name[: -len("_graph.json")]
        try:
            payload = json.loads(f.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        bucket = out.setdefault(
            run_id,
            {
                "fragments_path": payload.get("fragments_path"),
                "campaign": payload.get("campaign"),
                "style": payload.get("style"),
                "mtime": 0.0,
            },
        )
        mtime = f.stat().st_mtime
        if mtime >= float(bucket.get("mtime") or 0):
            bucket["fragments_path"] = payload.get("fragments_path") or bucket.get("fragments_path")
            bucket["campaign"] = payload.get("campaign") or bucket.get("campaign")
            bucket["style"] = payload.get("style") or bucket.get("style")
            bucket["mtime"] = mtime
    return out


def list_fragments_files() -> list[dict[str, Any]]:
    """Distinct fragments files seen across graph runs, newest run first.

    Each entry: ``{path, basename, run_count, latest_mtime}``.
    """
    idx = _graph_run_index()
    grouped: dict[str, dict[str, Any]] = {}
    for run_id, meta in idx.items():
        path = meta.get("fragments_path") or ""
        if not path:
            continue
        bucket = grouped.setdefault(
            path,
            {"path": path, "basename": Path(path).name, "run_count": 0, "latest_mtime": 0.0},
        )
        bucket["run_count"] += 1
        bucket["latest_mtime"] = max(bucket["latest_mtime"], float(meta.get("mtime") or 0))
    out = list(grouped.values())
    out.sort(key=lambda x: x.get("latest_mtime") or 0, reverse=True)
    for item in out:
        ts = item.pop("latest_mtime", 0.0)
        item["latest_iso"] = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat() if ts else None
    return out


def _filter_session_files_by_fragments(
    files: list[Path],
    fragments_path: str,
) -> list[Path]:
    """Drop session files whose run_id does not point at *fragments_path*."""
    if not fragments_path:
        return files
    idx = _graph_run_index()
    wanted = str(fragments_path)
    wanted_basename = Path(wanted).name
    out: list[Path] = []
    for f in files:
        rid = _extract_run_id(f)
        if not rid:
            # Sessions without run_id predate attack_runner; hide them when a
            # fragments filter is active so the dropdown only contains runs
            # tied to the selected file.
            continue
        meta = idx.get(rid)
        if not meta:
            continue
        run_path = str(meta.get("fragments_path") or "")
        if run_path == wanted or Path(run_path).name == wanted_basename:
            out.append(f)
    return out


def load_mcp_log_summaries() -> list[dict[str, Any]]:
    files = sorted(MCP_LOGS_DIR.glob("mcp_client_v1_*.log"), key=lambda p: p.stat().st_mtime, reverse=True)
    results: list[dict[str, Any]] = []
    for path in files[:20]:
        try:
            results.append(
                {
                    "file": path.name,
                    "bytes": path.stat().st_size,
                    "mtime": datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat(),
                }
            )
        except OSError:
            continue
    return results


def detect_tactic(prompt: str) -> str:
    lowered = prompt.lower()
    if any(x in lowered for x in ("nmap", "scan", "enumerate", "discover")):
        return "Discovery"
    if any(x in lowered for x in ("brute", "credential", "password", "login", "ldap", "ad ")):
        return "Credential Access"
    if any(x in lowered for x in ("copy", "find", "collect", "harvest", "search")):
        return "Collection"
    if any(x in lowered for x in ("encrypt", "archive", "compress", "tar", "zip", "openssl")):
        return "Staging"
    if any(x in lowered for x in ("exfil", "scp", "rclone", "upload", "transfer", "socket")):
        return "Exfiltration"
    if any(x in lowered for x in ("cron", "scheduled", "persistence", "registry", "run key")):
        return "Persistence"
    return "Execution"


def estimate_risk(prompt: str, tool_calls: list[str], tool_results: list[str]) -> float:
    score = 0.12
    text = " ".join([prompt, *tool_calls, *tool_results]).lower()
    rules = {
        0.18: ("nmap", "scan", "enumerate"),
        0.22: ("hydra", "brute", "password", "credential", "secretsdump"),
        0.20: ("find", "copy", "collect", "harvest", ".env", ".pem", ".sql"),
        0.24: ("encrypt", "openssl", "chacha", "aes", "archive", "tar"),
        0.30: ("scp", "exfil", "upload", "rclone", "drop"),
        0.16: ("cron", "scheduled", "persistence", "registry"),
    }
    for weight, terms in rules.items():
        if any(term in text for term in terms):
            score += weight
    return round(min(score, 0.98), 2)


def extract_tool_names(tool_calls: list[Any]) -> list[str]:
    names: list[str] = []
    for call in tool_calls:
        if isinstance(call, dict):
            name = str(call.get("name") or "").strip()
            if name:
                names.append(name)
            continue
        text = str(call)
        matches = re.findall(r'tool_call\("([^"]+)"', text)
        if matches:
            names.extend(matches)
            continue
        if text and " " not in text and "\n" not in text:
            names.append(text)
    return sorted(set(n for n in names if n))


def _seed_index(seeds: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    idx: dict[str, dict[str, Any]] = {}
    for seed in seeds:
        metadata = seed.get("metadata", {})
        sid = str(metadata.get("id", "")).upper()
        if sid:
            idx[sid] = seed
    return idx


def _attack_index(attacks: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    idx: dict[str, dict[str, Any]] = {}
    for attack in attacks:
        metadata = attack.get("metadata", {})
        aid = str(metadata.get("id", "")).upper()
        if aid:
            idx[aid] = attack
    return idx


def _normalize_attack_id(value: Any) -> str:
    """Normalize an attack/seed id into a stable lookup key."""
    text = str(value or "").strip().upper()
    text = re.sub(r"\s+", "_", text)
    return text


def _base_attack_id(value: str) -> str:
    """Strip common numeric suffixes like HONESTCUE_1000 -> HONESTCUE."""
    return re.sub(r"[_-]\d+$", "", value)


def _select_by_id(
    items: list[dict[str, Any]],
    idx: dict[str, dict[str, Any]],
    wanted: str,
) -> dict[str, Any] | None:
    if not wanted:
        return None

    direct = idx.get(wanted)
    if direct is not None:
        return direct

    base = _base_attack_id(wanted)
    if base and base in idx:
        return idx[base]

    # Fall back to prefix match: HONESTCUE matches HONESTCUE_1000, etc.
    if base:
        for key, value in idx.items():
            if key.startswith(base + "_") or key.startswith(base + "-"):
                return value

    # As a last resort, scan the list for any metadata id containing the base token.
    token = base or wanted
    for it in items:
        md = it.get("metadata", {})
        mid = _normalize_attack_id(md.get("id"))
        if token and token in mid:
            return it
    return None


def _parse_ts(value: Any) -> str | None:
    """Return an ISO timestamp string if *value* is non-empty, else None."""
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _ms_between(start_iso: str | None, end_iso: str | None) -> int | None:
    """Return milliseconds between two ISO timestamps, or None."""
    if not start_iso or not end_iso:
        return None
    try:
        t0 = datetime.fromisoformat(start_iso)
        t1 = datetime.fromisoformat(end_iso)
        return max(0, int((t1 - t0).total_seconds() * 1000))
    except (ValueError, TypeError):
        return None


def _group_queries(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Group runtime logs into query-level records, **per session_id**.

    A single attack_runner run produces N concurrent ``mcp_cli`` subprocesses
    (one per (seed, fragment)), each writing its own ``session_*.jsonl``.
    When the viewer loads a run it merges all those files and sorts events by
    timestamp. That means events from different sessions interleave — so any
    state machine that tracks a single ``current_query`` will mis-attribute
    iteration data the moment two fragments overlap. We instead key all per-run
    state on the event's ``session_id`` so each fragment's prompt, tool calls,
    results and verdict stay welded together.
    """

    def _new_iteration(iteration: int, prompt: str) -> dict[str, Any]:
        return {
            "iteration": iteration,
            "prompt": prompt,
            "assistant_previews": [],
            "assistant_full": "",
            "thinking_full": "",
            "assistant_messages": [],
            "llm_raw_fallback": None,
            "tool_calls": [],
            "tool_call_details": [],
            "tool_results": [],
            "tool_results_structured": [],
            "query_complete": None,
            "events": [],
            "ts_start": None,
            "ts_end": None,
        }

    def ensure_iteration(q: dict[str, Any], iteration: int) -> dict[str, Any]:
        iters = q["iterations"]
        if iteration not in iters:
            iters[iteration] = _new_iteration(iteration, q.get("prompt", ""))
            q["iteration_order"].append(iteration)
        return iters[iteration]

    # Per-session state maps. Keyed by ``session_id`` from each event.
    session_meta: dict[str, dict[str, Any]] = {}
    open_query: dict[str, dict[str, Any]] = {}
    latest_iter_by_session: dict[str, int] = {}
    queries: list[dict[str, Any]] = []

    # Some legacy events may lack ``session_id`` — funnel those into a single
    # bucket so they don't pollute every other session.
    DEFAULT_SID = "__default__"

    def _sid(event: dict[str, Any]) -> str:
        sid = event.get("session_id")
        return str(sid) if sid else DEFAULT_SID

    for event in events:
        kind = str(event.get("event") or "")
        sid = _sid(event)

        if kind == "session_start":
            session_meta[sid] = {
                "session_id": event.get("session_id"),
                "source_ip": event.get("source_ip"),
                "stage_index": event.get("stage_index"),
                "variation_index": event.get("variation_index"),
                "style": event.get("style"),
            }
            continue

        if kind == "user_query":
            # Close out any in-flight query for the same session before starting
            # a new one (rare — usually one user_query per session file).
            if sid in open_query:
                queries.append(open_query.pop(sid))
            meta = session_meta.get(sid, {})
            open_query[sid] = {
                "prompt": str(event.get("query") or ""),
                "iterations": {},
                "iteration_order": [],
                "ts_start": _parse_ts(event.get("ts")),
                "ts_end": None,
                "verdict": None,
                "verdict_justification": "",
                "verdict_classifier": "",
                "style": meta.get("style"),
                **meta,
            }
            latest_iter_by_session[sid] = 0
            continue

        current_query = open_query.get(sid)
        if current_query is None:
            continue

        iteration_raw = event.get("iteration")
        try:
            iteration = int(iteration_raw) if iteration_raw is not None else None
        except (TypeError, ValueError):
            iteration = None

        event_ts = _parse_ts(event.get("ts"))
        latest_iter = latest_iter_by_session.get(sid, 0)

        if kind == "verdict":
            # Prefer llm_judge verdict over keyword when both are present
            if current_query.get("verdict") is None or event.get("classifier") == "llm_judge":
                current_query["verdict"] = event.get("verdict", "UNCLEAR")
                current_query["verdict_justification"] = str(event.get("justification") or "")
                current_query["verdict_classifier"] = str(event.get("classifier") or "keyword")
            continue

        if kind == "iteration_start":
            if iteration is None:
                latest_iter += 1
                iteration = latest_iter
            latest_iter = max(latest_iter, iteration)
            latest_iter_by_session[sid] = latest_iter
            turn = ensure_iteration(current_query, iteration)
            turn["events"].append(event)
            if event_ts and not turn["ts_start"]:
                turn["ts_start"] = event_ts
            continue

        if iteration is None:
            iteration = latest_iter if latest_iter > 0 else 1
        latest_iter = max(latest_iter, iteration)
        latest_iter_by_session[sid] = latest_iter
        turn = ensure_iteration(current_query, iteration)
        turn["events"].append(event)
        if event_ts:
            if not turn["ts_start"]:
                turn["ts_start"] = event_ts
            turn["ts_end"] = event_ts
            current_query["ts_end"] = event_ts

        if kind == "assistant_response":
            preview = str(event.get("content_preview") or "")
            if preview:
                turn["assistant_previews"].append(preview)
            full = str(event.get("content_full") or "")
            if full:
                turn["assistant_full"] = full
            thinking = str(event.get("thinking_full") or "")
            if thinking:
                turn["thinking_full"] = thinking
            calls = event.get("tool_calls") or []
            if isinstance(calls, list):
                turn["tool_calls"].extend([str(c) for c in calls])
            details = event.get("tool_call_details") or []
            msg_details: list[dict[str, str]] = []
            if isinstance(details, list):
                for item in details:
                    if isinstance(item, dict):
                        normalized = {
                            "name": str(item.get("name") or ""),
                            "arguments_preview": str(item.get("arguments_preview") or ""),
                        }
                        turn["tool_call_details"].append(normalized)
                        msg_details.append(normalized)
            turn["assistant_messages"].append(
                {
                    "is_final": bool(event.get("is_final", False)),
                    "has_content": bool(event.get("has_content", False)),
                    "content_preview": preview,
                    "content_full": full,
                    "thinking_preview": str(event.get("thinking_preview") or ""),
                    "thinking_full": thinking,
                    "tool_calls": [str(c) for c in calls] if isinstance(calls, list) else [],
                    "tool_call_details": msg_details,
                }
            )
        elif kind == "llm_response_received":
            turn["llm_raw_fallback"] = {
                "content_preview": str(event.get("content_preview") or ""),
                "content_full": str(event.get("content_full") or ""),
                "thinking_preview": str(event.get("thinking_preview") or ""),
                "thinking_full": str(event.get("thinking_full") or ""),
            }
        elif kind == "tool_result":
            preview = str(event.get("result_preview") or "")
            turn["tool_results"].append(preview)
            turn["tool_results_structured"].append(
                {
                    "tool": str(event.get("tool") or ""),
                    "success": bool(event.get("success", False)),
                    "result_preview": preview,
                }
            )
        elif kind == "query_complete":
            turn["query_complete"] = event

    # Drain any sessions that were still mid-flight at end-of-stream.
    for sid, q in open_query.items():
        queries.append(q)
    open_query.clear()
    if not queries:
        return []

    # Sort the finalised queries by their first-seen timestamp so the trace
    # cards still appear in chronological order across concurrent sessions.
    queries.sort(key=lambda q: q.get("ts_start") or "")

    merged_queries: list[dict[str, Any]] = []
    for q in queries:
        order = sorted(q["iteration_order"])
        if not order:
            continue

        merged = _new_iteration(order[0], q.get("prompt", ""))
        merged["iteration"] = order[0]
        merged["iterations_detail"] = []
        merged["ts_start"] = q.get("ts_start")
        merged["ts_end"] = q.get("ts_end")
        merged["session_id"] = q.get("session_id")
        merged["source_ip"] = q.get("source_ip")
        merged["stage_index"] = q.get("stage_index")
        merged["variation_index"] = q.get("variation_index")
        merged["style"] = q.get("style")
        merged["verdict"] = q.get("verdict")
        merged["verdict_justification"] = q.get("verdict_justification", "")
        merged["verdict_classifier"] = q.get("verdict_classifier", "")

        for it in order:
            turn = q["iterations"][it]
            if not turn["assistant_messages"] and isinstance(turn.get("llm_raw_fallback"), dict):
                fb = turn["llm_raw_fallback"]
                turn["assistant_messages"].append(
                    {
                        "is_final": True,
                        "has_content": bool(fb.get("content_full")),
                        "content_preview": str(fb.get("content_preview") or ""),
                        "content_full": str(fb.get("content_full") or ""),
                        "thinking_preview": str(fb.get("thinking_preview") or ""),
                        "thinking_full": str(fb.get("thinking_full") or ""),
                        "tool_calls": [],
                        "tool_call_details": [],
                    }
                )
                if not turn.get("assistant_full"):
                    turn["assistant_full"] = str(fb.get("content_full") or "")
                if not turn.get("thinking_full"):
                    turn["thinking_full"] = str(fb.get("thinking_full") or "")

            iter_duration_ms = _ms_between(turn.get("ts_start"), turn.get("ts_end"))
            merged["iterations_detail"].append(
                {
                    "iteration": it,
                    "thinking_full": str(turn.get("thinking_full") or ""),
                    "assistant_content": str(turn.get("assistant_full") or ""),
                    "assistant_messages": list(turn["assistant_messages"]),
                    "tool_calls": list(turn["tool_calls"]),
                    "tool_call_details": list(turn["tool_call_details"]),
                    "tool_results_structured": list(turn["tool_results_structured"]),
                    "duration_ms": iter_duration_ms,
                }
            )

            merged["assistant_previews"].extend(turn["assistant_previews"])
            if turn.get("assistant_full"):
                merged["assistant_full"] = str(turn["assistant_full"])
            if turn.get("thinking_full"):
                merged["thinking_full"] = str(turn["thinking_full"])
            merged["assistant_messages"].extend(turn["assistant_messages"])
            merged["tool_calls"].extend(turn["tool_calls"])
            merged["tool_call_details"].extend(turn["tool_call_details"])
            merged["tool_results"].extend(turn["tool_results"])
            merged["tool_results_structured"].extend(turn["tool_results_structured"])
            if turn.get("query_complete"):
                merged["query_complete"] = turn["query_complete"]
            merged["events"].extend(turn["events"])

        merged_queries.append(merged)

    return merged_queries


def _extract_run_id(path: Path) -> str | None:
    """Read the first event from a session JSONL and return its run_id."""
    try:
        for line in path.open(encoding="utf-8"):
            line = line.strip()
            if not line:
                continue
            event = _safe_json_loads(line)
            if event and event.get("event") == "session_start":
                rid = event.get("run_id")
                return str(rid) if rid else None
            break
    except OSError:
        pass
    return None


def _find_sibling_sessions(session_path: Path, run_id: str) -> list[Path]:
    """Find every other session file that belongs to the same ``run_id``.

    With the per-run directory layout (``logs/<run_id>/session_*.jsonl``)
    every sibling lives in the same directory; we still scan the top-level
    ``logs/`` as a backstop so legacy session files (no per-run dir) are
    matched purely by their embedded ``run_id`` and never misattributed.
    """
    candidates = list(session_path.parent.glob("session_*.jsonl"))
    if session_path.parent != LOGS_DIR:
        candidates += list(LOGS_DIR.glob("session_*.jsonl"))
    siblings: list[Path] = []
    for candidate in sorted(set(candidates)):
        if candidate == session_path:
            continue
        if _extract_run_id(candidate) == run_id:
            siblings.append(candidate)
    return sorted(siblings, key=lambda p: p.name)


def _load_passes_for_run(run_id: str | None) -> dict[str, Any] | None:
    """Return ``{seeds, passes, ...}`` aggregated from per-seed chain files.

    Falls back to the legacy single-file ``<run_id>_passes.json`` if it exists.
    """
    if not run_id:
        return None

    chain_files = _chain_files_for_run(run_id)
    if chain_files:
        rows: list[tuple[int, dict[str, Any]]] = []
        for f in chain_files:
            parsed = _parse_chain_filename(f)
            if parsed is None:
                continue
            _rid, seed, _camp = parsed
            try:
                payload = json.loads(f.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            rows.append((seed, payload))
        if rows:
            rows.sort(key=lambda r: r[0])
            head = rows[0][1]
            return {
                "run_id": run_id,
                "campaign": head.get("campaign"),
                "style": head.get("style"),
                "fragments_path": head.get("fragments_path"),
                "seeds": [seed for seed, _ in rows],
                "passes": [bool(payload.get("passed")) for _, payload in rows],
                "target_model": head.get("target_model"),
                "target_backend": head.get("target_backend"),
                "judge_model": head.get("judge_model"),
                "generated_at": head.get("generated_at"),
                "chains": [payload for _, payload in rows],
            }

    legacy = RESULTS_RUNS_DIR / f"{run_id}_passes.json"
    if legacy.exists():
        try:
            return json.loads(legacy.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
    return None


def _passes_lookup(passes: dict[str, Any] | None) -> dict[int, bool]:
    """Build {seed -> bool} from a passes file payload."""
    if not passes:
        return {}
    seeds = passes.get("seeds") or []
    bools = passes.get("passes") or []
    out: dict[int, bool] = {}
    for s, p in zip(seeds, bools):
        try:
            out[int(s)] = bool(p)
        except (TypeError, ValueError):
            continue
    return out


def _fragment_outcomes_lookup(
    passes: dict[str, Any] | None,
) -> dict[tuple[int, int], dict[str, Any]]:
    """``{(seed, fragment_index) -> {passed, verdict, justification, classifier}}``.

    Single source of truth for the trace card's verdict, sourced from the
    success-judge that ``attack_runner`` ran post-execution. The viewer prefers
    this over the per-iteration detector verdicts (which classify ANSWERED /
    REFUSED only and do not reason about whether the *fragment goal* was met).
    """
    if not passes:
        return {}
    out: dict[tuple[int, int], dict[str, Any]] = {}
    for chain in passes.get("chains") or []:
        if not isinstance(chain, dict):
            continue
        try:
            seed = int(chain.get("seed"))
        except (TypeError, ValueError):
            continue
        for frag in chain.get("fragments") or []:
            if not isinstance(frag, dict):
                continue
            fidx_raw = frag.get("fragment_index")
            try:
                fidx = int(fidx_raw)
            except (TypeError, ValueError):
                continue
            out[(seed, fidx)] = {
                "passed": bool(frag.get("passed")),
                "verdict": frag.get("verdict"),
                "justification": str(frag.get("justification") or ""),
                "classifier": str(frag.get("classifier") or ""),
            }
    return out


def _assemble_graph_payload(run_id: str) -> dict[str, Any] | None:
    """Build the legacy ``{variations: [...], ...}`` payload from per-seed graph files.

    Returns ``None`` if no per-seed files exist (caller should try the legacy
    single-file path).
    """
    files = _graph_files_for_run(run_id)
    if not files:
        return None
    rows: list[tuple[int, Path, dict[str, Any]]] = []
    for f in files:
        parsed = _parse_graph_filename(f)
        if parsed is None:
            continue
        _rid, seed, _camp = parsed
        try:
            payload = json.loads(f.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        rows.append((seed, f, payload))
    if not rows:
        return None
    rows.sort(key=lambda r: r[0])
    head = rows[0][2]
    variations: list[dict[str, Any]] = []
    for _seed, _path, payload in rows:
        variation = payload.get("variation")
        if isinstance(variation, dict):
            variations.append(variation)
    return {
        "run_id": run_id,
        "campaign": head.get("campaign"),
        "style": head.get("style"),
        "fragments_path": head.get("fragments_path"),
        "started_at": head.get("started_at"),
        "ended_at": head.get("ended_at"),
        "target_model": head.get("target_model"),
        "target_backend": head.get("target_backend"),
        "llm_product": head.get("llm_product"),
        "judge_model": head.get("judge_model"),
        "variations": variations,
    }


def list_graph_runs() -> list[dict[str, Any]]:
    """Return one row per attack_runner run, aggregated across per-seed files.

    Falls back to legacy ``<run_id>_graph.json`` files when present.
    """
    if not RESULTS_RUNS_DIR.exists():
        return []
    out: list[dict[str, Any]] = []
    seen: set[str] = set()

    # Group per-seed graph files by run_id.
    by_run: dict[str, list[Path]] = {}
    for f in _list_graph_files():
        parsed = _parse_graph_filename(f)
        if parsed is None:
            continue
        by_run.setdefault(parsed[0], []).append(f)

    for run_id, files in by_run.items():
        files.sort(key=lambda p: p.stat().st_mtime)
        try:
            head_payload = json.loads(files[-1].read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        passes_payload = _load_passes_for_run(run_id) or {}
        passes_vec = passes_payload.get("passes") or []
        latest_mtime = max(p.stat().st_mtime for p in files)
        total_bytes = sum(p.stat().st_size for p in files)
        out.append(
            {
                "run_id": run_id,
                "campaign": head_payload.get("campaign"),
                "style": head_payload.get("style"),
                "started_at": head_payload.get("started_at"),
                "ended_at": head_payload.get("ended_at"),
                "num_variations": len(files),
                "num_passed": sum(1 for p in passes_vec if p),
                "fragments_path": head_payload.get("fragments_path"),
                "mtime": datetime.fromtimestamp(latest_mtime, tz=timezone.utc).isoformat(),
                "bytes": total_bytes,
            }
        )
        seen.add(run_id)

    # Legacy single-file runs that haven't been reformatted to per-seed yet.
    for f in RESULTS_RUNS_DIR.glob("*_graph.json"):
        if _parse_graph_filename(f) is not None:
            continue
        run_id = f.name[: -len("_graph.json")]
        if run_id in seen:
            continue
        try:
            payload = json.loads(f.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        passes_payload = _load_passes_for_run(run_id)
        passes_vec = (passes_payload or {}).get("passes", []) if passes_payload else []
        out.append(
            {
                "run_id": run_id,
                "campaign": payload.get("campaign"),
                "style": payload.get("style"),
                "started_at": payload.get("started_at"),
                "ended_at": payload.get("ended_at"),
                "num_variations": len(payload.get("variations", []) or []),
                "num_passed": sum(1 for p in passes_vec if p),
                "fragments_path": payload.get("fragments_path"),
                "mtime": datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc).isoformat(),
                "bytes": f.stat().st_size,
            }
        )

    out.sort(key=lambda x: x.get("mtime") or "", reverse=True)
    return out


def load_graph_run(run_id: str) -> dict[str, Any] | None:
    """Assemble a single viewer payload for *run_id* from per-seed files."""
    graph = _assemble_graph_payload(run_id)
    if graph is None:
        legacy = RESULTS_RUNS_DIR / f"{run_id}_graph.json"
        if not legacy.exists():
            return None
        try:
            graph = json.loads(legacy.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
    passes_payload = _load_passes_for_run(run_id) or {}
    return {
        "run_id": run_id,
        "graph": graph,
        "passes": passes_payload,
    }


def build_artifact_bundle(
    *,
    session_path: Path | None = None,
    seeds: list[dict[str, Any]] | None = None,
    attacks: list[dict[str, Any]] | None = None,
    session_events: list[dict[str, Any]] | None = None,
) -> ArtifactBundle:
    loaded_seeds = seeds if seeds is not None else load_seeds()
    loaded_attacks = attacks if attacks is not None else load_attack_toml()
    if session_events is not None:
        events = session_events
    else:
        candidate = session_path or (list_session_files()[0] if list_session_files() else None)
        events = load_jsonl(candidate) if candidate else []

        if candidate:
            run_id = _extract_run_id(candidate)
            if run_id:
                siblings = _find_sibling_sessions(candidate, run_id)
                for sib in siblings:
                    events.extend(load_jsonl(sib))
                events.sort(key=lambda e: str(e.get("ts", "")))

    source = {
        "session_file": session_path.name if session_path else None,
        "seeds_count": len(loaded_seeds),
        "attacks_count": len(loaded_attacks),
    }
    return ArtifactBundle(
        seeds=loaded_seeds,
        attacks=loaded_attacks,
        session_events=events,
        mcp_logs=load_mcp_log_summaries(),
        source=source,
    )


def _load_graph_for_run(run_id: str | None) -> dict[str, Any] | None:
    """Return the assembled graph payload for *run_id*, or None.

    Tries per-seed files first, then falls back to legacy ``<run_id>_graph.json``.
    """
    if not run_id:
        return None
    assembled = _assemble_graph_payload(run_id)
    if assembled is not None:
        return assembled
    legacy = RESULTS_RUNS_DIR / f"{run_id}_graph.json"
    if not legacy.exists():
        return None
    try:
        return json.loads(legacy.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _canonical_dag_fragments(graph: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Pull a canonical fragment list (produces/consumes/role/passed) from a
    graph payload so the live viewer can render the same DAG that the graph
    viewer shows. We use the first variation as the shape (all variations of a
    deterministic picker share the same fragment skeleton).
    """
    if not graph:
        return []
    variations = graph.get("variations") or []
    if not variations:
        return []
    sample = variations[0].get("fragments") or []
    out: list[dict[str, Any]] = []
    for f in sample:
        if not isinstance(f, dict):
            continue
        out.append({
            "fragment_index": f.get("fragment_index"),
            "role": f.get("role"),
            "phase": f.get("phase"),
            "produces": list(f.get("produces") or []),
            "consumes": list(f.get("consumes") or []),
        })
    return out


def _canonical_dag_from_fragments_file(path: str | Path | None) -> list[dict[str, Any]]:
    """Derive a canonical fragment skeleton (index/role/produces/consumes) from
    the source fragments JSON without needing a graph file. Used as a fallback
    so the live viewer can show the DAG even before ``attack_runner`` has
    flushed ``<run_id>_graph.json`` (e.g. while the run is still in progress).
    """
    if not path:
        return []
    p = Path(path)
    if not p.exists():
        return []
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    variations = doc.get("variations") or []
    if not isinstance(variations, list) or not variations:
        return []
    sample = variations[0]
    if not isinstance(sample, dict):
        return []
    fragments = sample.get("fragments") or []
    out: list[dict[str, Any]] = []
    for f in fragments:
        if not isinstance(f, dict):
            continue
        out.append({
            "fragment_index": f.get("fragment_index"),
            "role": f.get("role"),
            "phase": f.get("phase"),
            "produces": list(f.get("produces") or []),
            "consumes": list(f.get("consumes") or []),
        })
    return out


def _resolve_fallback_fragments_path(
    explicit: str | None,
    attack_id: str | None,
) -> str | None:
    """Best-effort lookup for a fragments file when the live session has no
    matching ``_graph.json`` yet.

    Order of preference:
      1. ``?fragments=<path>`` passed by the viewer (frontend selector).
      2. The most-recent graph run (which exposes ``fragments_path``).
      3. Any registered fragments file whose basename token matches the
         session's ``attack_id`` (e.g. ``PROMPTSTEAL`` → ``promptsteal_*.json``).
      4. Any ``*_fragments.json`` directly under ``results/`` whose basename
         token matches the attack_id.
    """
    if explicit and Path(explicit).exists():
        return explicit
    files = list_fragments_files()

    def _existing(path: str) -> str | None:
        p = Path(path)
        if p.exists():
            return str(p)
        # Container paths (e.g. ``/app/results/foo.json``) won't exist on the
        # host, but the basename will under ``results/`` — translate.
        host_alt = REPO_ROOT / "results" / p.name
        return str(host_alt) if host_alt.exists() else None

    if explicit:
        wanted_base = Path(explicit).name
        host_alt = REPO_ROOT / "results" / wanted_base
        if host_alt.exists():
            return str(host_alt)
        for f in files:
            if Path(f["path"]).name == wanted_base:
                hit = _existing(f["path"])
                if hit:
                    return hit

    token = ""
    if attack_id:
        token = re.sub(r"[_-]\d+$", "", str(attack_id)).lower()

    if token:
        for f in files:
            if token in f["basename"].lower():
                hit = _existing(f["path"])
                if hit:
                    return hit
        # Scan the local ``results/`` directory directly — covers the case
        # where the graph file index is empty (fresh checkout, run still in
        # progress and not flushed, etc.).
        results_dir = REPO_ROOT / "results"
        if results_dir.exists():
            for cand in sorted(results_dir.glob("*_fragments.json")):
                if token in cand.name.lower():
                    return str(cand)

    if files:
        hit = _existing(files[0]["path"])
        if hit:
            return hit

    # Last resort: most-recent ``*_fragments.json`` in ``results/``.
    results_dir = REPO_ROOT / "results"
    if results_dir.exists():
        cands = sorted(
            results_dir.glob("*_fragments.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if cands:
            return str(cands[0])
    return None


def normalize_bundle(
    bundle: ArtifactBundle,
    *,
    fragments_filter: str | None = None,
) -> dict[str, Any]:
    events = bundle.session_events
    session_start = next((e for e in events if e.get("event") == "session_start"), {})
    attack_id = _normalize_attack_id(session_start.get("attack_id"))
    run_id = session_start.get("run_id")
    run_style = session_start.get("style")
    passes_payload = _load_passes_for_run(run_id)
    passes_by_seed = _passes_lookup(passes_payload)
    fragment_outcomes = _fragment_outcomes_lookup(passes_payload)
    # Run-level model labels — surfaced once on the run + on every trace card.
    chain_head = ((passes_payload or {}).get("chains") or [{}])[0] if passes_payload else {}
    target_model = (passes_payload or {}).get("target_model") or chain_head.get("target_model")
    target_backend = (passes_payload or {}).get("target_backend") or chain_head.get("target_backend")
    judge_model = (passes_payload or {}).get("judge_model") or chain_head.get("judge_model")
    if target_model and target_backend:
        target_label = f"{target_backend}:{target_model}"
    elif target_model:
        target_label = str(target_model)
    else:
        target_label = None
    graph_payload = _load_graph_for_run(run_id)
    canonical_fragments = _canonical_dag_fragments(graph_payload)
    graph_fragments_path = (graph_payload or {}).get("fragments_path") if graph_payload else None

    # Fallback: if no <run_id>_graph.json exists yet (run in progress, or
    # legacy session), build the canonical DAG straight from the fragments
    # JSON file. This way the live viewer always shows the dependency picture
    # alongside the trace, even before attack_runner finalises results.
    if not canonical_fragments:
        fb_path = _resolve_fallback_fragments_path(fragments_filter, attack_id)
        if fb_path:
            canonical_fragments = _canonical_dag_from_fragments_file(fb_path)
            if canonical_fragments and not graph_fragments_path:
                graph_fragments_path = fb_path
    seed_idx = _seed_index(bundle.seeds)
    attack_idx = _attack_index(bundle.attacks)
    seed = _select_by_id(bundle.seeds, seed_idx, attack_id)
    attack = _select_by_id(bundle.attacks, attack_idx, attack_id)

    if seed is None and bundle.seeds:
        seed = bundle.seeds[0]
    if attack is None and bundle.attacks:
        attack = bundle.attacks[0]

    seed_metadata = (seed or {}).get("metadata", {})
    stages = (seed or {}).get("attack_stages", [])
    fragments = (attack or {}).get("fragments", [])
    campaign_name = seed_metadata.get("id") or attack_id or "UNKNOWN"

    fragment_rows: list[dict[str, Any]] = []
    attack_fragment_map = {int(f.get("index", i)): f for i, f in enumerate(fragments) if isinstance(f, dict)}
    for stage in stages:
        index = int(stage.get("index", len(fragment_rows)))
        mapped = attack_fragment_map.get(index, {})
        vars_list = mapped.get("variations", [])
        if not isinstance(vars_list, list):
            vars_list = []
        fragment_rows.append(
            {
                "index": index,
                "description": stage.get("description", ""),
                "mitre_tactic": stage.get("mitre_tactic", ""),
                "mitre_technique": stage.get("mitre_technique", ""),
                "mitre_technique_name": stage.get("mitre_technique_name", ""),
                "baseline_prompt": stage.get("baseline_prompt", ""),
                "variations": [
                    {"style": v.get("style", "unknown"), "prompt": v.get("prompt", "")}
                    for v in vars_list
                    if isinstance(v, dict)
                ],
            }
        )

    grouped_queries = _group_queries(events)
    traces: list[dict[str, Any]] = []
    tactics_seen: list[str] = []

    ordered_fragment_rows = sorted(fragment_rows, key=lambda row: int(row.get("index", 0)))
    fragment_by_index = {int(r.get("index", i)): r for i, r in enumerate(ordered_fragment_rows)}

    for idx, query in enumerate(grouped_queries, start=1):
        prompt = str(query.get("prompt") or "")
        assistant_messages = [x for x in query.get("assistant_messages", []) if isinstance(x, dict)]
        tool_calls = [str(x) for x in query.get("tool_calls", [])]
        tool_call_details = [x for x in query.get("tool_call_details", []) if isinstance(x, dict)]
        tool_results = [str(x) for x in query.get("tool_results", [])]
        tool_results_structured = [
            x for x in query.get("tool_results_structured", []) if isinstance(x, dict)
        ]
        query_stage_idx = query.get("stage_index")
        if query_stage_idx is not None:
            stage_meta = fragment_by_index.get(int(query_stage_idx), {})
        else:
            stage_meta = ordered_fragment_rows[idx - 1] if idx - 1 < len(ordered_fragment_rows) else {}
        tactic = str(stage_meta.get("mitre_tactic") or detect_tactic(prompt))
        if tactic not in tactics_seen:
            tactics_seen.append(tactic)
        risk = estimate_risk(prompt, tool_calls, tool_results)
        kcc = round(min(len(tactics_seen) / 6.0, 1.0), 2)
        iterations_detail = [
            x for x in query.get("iterations_detail", []) if isinstance(x, dict)
        ]
        step_duration_ms = _ms_between(query.get("ts_start"), query.get("ts_end"))
        effective_fragment_index = query_stage_idx if query_stage_idx is not None else stage_meta.get("index")

        # variation_index is the picked-attack seed when attack_runner spawned this trace.
        seed_value = query.get("variation_index")
        try:
            seed_int = int(seed_value) if seed_value is not None else None
        except (TypeError, ValueError):
            seed_int = None
        # Resolve a SINGLE pass/fail verdict per fragment.
        #
        # Authority order:
        #   1. attack_runner success-judge for this exact (seed, fragment) →
        #      authoritative PASS / FAIL with judge justification.
        #   2. variation-level passes vector (per-seed) → coarse fallback while
        #      a chain file hasn't been written yet.
        #   3. mcp_cli's per-iteration detector verdict (ANSWERED/REFUSED) →
        #      live-preview only; never overrides the success judge.
        passed_value: bool | None = None
        verdict_value = query.get("verdict")
        verdict_just = query.get("verdict_justification", "")
        verdict_cls = query.get("verdict_classifier", "")

        outcome_key = (
            (seed_int, int(effective_fragment_index))
            if seed_int is not None and effective_fragment_index is not None
            else None
        )
        outcome = fragment_outcomes.get(outcome_key) if outcome_key is not None else None
        if outcome is not None:
            passed_value = outcome["passed"]
            # The success judge is the source of truth — overwrite the inline
            # detector signal so the card never shows two contradictory verdicts.
            verdict_value = outcome["verdict"] or ("PASS" if passed_value else "FAIL")
            verdict_just = outcome["justification"]
            verdict_cls = outcome["classifier"] or "llm_judge"
        elif seed_int is not None and seed_int in passes_by_seed:
            passed_value = passes_by_seed[seed_int]

        traces.append(
            {
                "step": idx,
                "iteration": query.get("iteration", idx),
                "prompt": prompt,
                "assistant_messages": assistant_messages,
                "tool_calls": tool_calls,
                "tool_call_details": tool_call_details,
                "tool_results": tool_results,
                "tool_results_structured": tool_results_structured,
                "iterations_detail": iterations_detail,
                "total_iterations": len(iterations_detail),
                "total_tool_calls": sum(len(it.get("tool_calls", [])) for it in iterations_detail),
                "assistant_preview": (query.get("assistant_previews") or [""])[0],
                "assistant_full": str(query.get("assistant_full") or ""),
                "thinking_full": str(query.get("thinking_full") or ""),
                "tactic": tactic,
                "risk": risk,
                "kcc": kcc,
                "toolkit_set": extract_tool_names(tool_call_details or tool_calls),
                "alert": kcc > 0.7 or risk > 0.85,
                "fragment_index": effective_fragment_index,
                "fragment_description": str(stage_meta.get("description") or ""),
                "mitre_technique": str(stage_meta.get("mitre_technique") or ""),
                "mitre_technique_name": str(stage_meta.get("mitre_technique_name") or ""),
                "baseline_prompt": str(stage_meta.get("baseline_prompt") or ""),
                "alt_phrasings": [
                    str(v.get("prompt") or "")
                    for v in stage_meta.get("variations", [])
                    if isinstance(v, dict) and str(v.get("prompt") or "").strip()
                ],
                "started_at": query.get("ts_start"),
                "ended_at": query.get("ts_end"),
                "duration_ms": step_duration_ms,
                "session_id": query.get("session_id"),
                "source_ip": query.get("source_ip"),
                "stage_index": query.get("stage_index"),
                "variation_index": query.get("variation_index"),
                "seed": seed_int,
                "style": query.get("style") or run_style,
                "passed": passed_value,
                "verdict": verdict_value,
                "verdict_justification": verdict_just,
                "verdict_classifier": verdict_cls,
                "target_model": target_model,
                "target_backend": target_backend,
                "target_label": target_label,
                "judge_model": judge_model,
            }
        )

    campaign = {
        "id": campaign_name,
        "title": seed_metadata.get("description") or f"Campaign {campaign_name}",
        "technique": seed_metadata.get("technique"),
        "technique_name": seed_metadata.get("technique_name"),
        "tags": seed_metadata.get("tags", []),
        "aliases": seed_metadata.get("aliases", []),
        "session_count": len(traces),
    }

    tactic_totals: dict[str, int] = {}
    for row in fragment_rows:
        tactic = str(row.get("mitre_tactic") or "unknown")
        tactic_totals[tactic] = tactic_totals.get(tactic, 0) + 1

    gnn_nodes = [
        {
            "id": f"S{item['step']}",
            "label": item["tactic"],
            "risk": item["risk"],
            "kcc": item["kcc"],
            "tool_count": len(item["tool_calls"]),
        }
        for item in traces
    ]

    edges = []
    for i in range(len(gnn_nodes) - 1):
        edges.append({"from": gnn_nodes[i]["id"], "to": gnn_nodes[i + 1]["id"], "type": "temporal"})

    latest_kcc = traces[-1]["kcc"] if traces else 0.0
    latest_alert = bool(traces[-1]["alert"]) if traces else False

    all_ts = [_parse_ts(e.get("ts")) for e in events]
    all_ts = [t for t in all_ts if t]
    run_started = min(all_ts) if all_ts else None
    run_ended = max(all_ts) if all_ts else None
    total_duration_ms = _ms_between(run_started, run_ended)

    seed_set = sorted({t["seed"] for t in traces if t.get("seed") is not None})
    pass_vector = [bool(passes_by_seed[s]) for s in seed_set if s in passes_by_seed] if passes_by_seed else []
    pass_count = sum(1 for v in pass_vector if v)

    return {
        "run": {
            "session_file": bundle.source.get("session_file"),
            "model": session_start.get("model"),
            "server": session_start.get("server"),
            "attack_id": attack_id or campaign_name,
            "campaign": session_start.get("campaign"),
            "session_id": session_start.get("session_id"),
            "source_ip": session_start.get("source_ip"),
            "run_id": run_id,
            "style": run_style,
            "seeds": seed_set,
            "passes": pass_vector,
            "num_passed": pass_count,
            "num_variations": len(seed_set),
            "events": len(events),
            "alerts": latest_alert,
            "kcc": latest_kcc,
            "started_at": run_started,
            "ended_at": run_ended,
            "total_duration_ms": total_duration_ms,
            "fragments_path": graph_fragments_path,
            "dag_fragments": canonical_fragments,
            "target_model": target_model,
            "target_backend": target_backend,
            "target_label": target_label,
            "judge_model": judge_model,
        },
        "campaigns": [campaign],
        "fragments": fragment_rows,
        "traces": traces,
        "mitre": {
            "coverage": tactic_totals,
            "techniques": [
                {
                    "technique": row.get("mitre_technique"),
                    "name": row.get("mitre_technique_name"),
                    "tactic": row.get("mitre_tactic"),
                }
                for row in fragment_rows
            ],
        },
        "gnn": {
            "nodes": gnn_nodes,
            "edges": edges,
            "classification": "MALICIOUS" if latest_alert else ("SUSPICIOUS" if latest_kcc > 0.4 else "MONITORING"),
        },
        "demo": {
            "queue": gnn_nodes,
            "kcc": latest_kcc,
            "state": "alert" if latest_alert else "monitoring",
        },
        "sources": {
            "seeds": len(bundle.seeds),
            "attacks": len(bundle.attacks),
            "session_events": len(bundle.session_events),
            "mcp_logs": bundle.mcp_logs,
        },
    }


def _json_response(handler: BaseHTTPRequestHandler, payload: Any, status: int = 200) -> None:
    body = json.dumps(payload, indent=2).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class ViewerHandler(BaseHTTPRequestHandler):
    server_version = "FragGuardViewer/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _query(self) -> dict[str, str]:
        from urllib.parse import parse_qs, urlsplit

        qs = urlsplit(self.path).query
        return {k: v[0] for k, v in parse_qs(qs).items() if v}

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        params = self._query()
        fragments_filter = params.get("fragments", "").strip()
        if path == "/api/fragments-files":
            _json_response(self, {"files": list_fragments_files()})
            return
        if path == "/api/runs":
            files = list_session_files()
            if fragments_filter:
                files = _filter_session_files_by_fragments(files, fragments_filter)
            payload = []
            for f in files[:50]:
                entry: dict[str, Any] = {
                    "id": f.name,
                    "mtime": datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc).isoformat(),
                    "bytes": f.stat().st_size,
                }
                rid = _extract_run_id(f)
                if rid:
                    entry["run_id"] = rid
                payload.append(entry)
            _json_response(self, {"runs": payload})
            return
        if path == "/api/run/latest":
            files = list_session_files()
            if fragments_filter:
                files = _filter_session_files_by_fragments(files, fragments_filter)
            if not files:
                _json_response(self, {"error": "no session logs found"}, status=404)
                return
            bundle = build_artifact_bundle(session_path=files[0])
            _json_response(self, normalize_bundle(bundle, fragments_filter=fragments_filter))
            return
        if path == "/api/graph/runs":
            runs = list_graph_runs()
            if fragments_filter:
                wanted_basename = Path(fragments_filter).name
                runs = [
                    r for r in runs
                    if (r.get("fragments_path") == fragments_filter
                        or Path(r.get("fragments_path") or "").name == wanted_basename)
                ]
            _json_response(self, {"runs": runs})
            return
        if path.startswith("/api/graph/"):
            run_id = path.rsplit("/", 1)[-1]
            payload = load_graph_run(run_id)
            if payload is None:
                _json_response(self, {"error": f"graph run not found: {run_id}"}, status=404)
                return
            _json_response(self, payload)
            return
        if path.startswith("/api/run/"):
            run_id = path.rsplit("/", 1)[-1]
            session_path = LOGS_DIR / run_id
            # Per-run isolation puts files at logs/<attack_run_id>/<file>.jsonl;
            # fall back to a recursive search so the route still works.
            if not session_path.exists():
                matches = list(LOGS_DIR.glob(f"*/{run_id}"))
                session_path = matches[0] if matches else session_path
            if not session_path.exists():
                _json_response(self, {"error": f"run not found: {run_id}"}, status=404)
                return
            bundle = build_artifact_bundle(session_path=session_path)
            _json_response(self, normalize_bundle(bundle, fragments_filter=fragments_filter))
            return
        self._serve_static(path)

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path != "/api/normalize_upload":
            _json_response(self, {"error": "unknown endpoint"}, status=404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        try:
            raw = self.rfile.read(length).decode("utf-8")
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            _json_response(self, {"error": "invalid JSON payload"}, status=400)
            return

        seeds_payload = payload.get("seeds", [])
        attacks_payload = payload.get("attacks", [])
        session_events = payload.get("session_events", [])
        if not isinstance(seeds_payload, list) or not isinstance(attacks_payload, list) or not isinstance(session_events, list):
            _json_response(self, {"error": "expected array fields: seeds, attacks, session_events"}, status=400)
            return

        bundle = build_artifact_bundle(
            seeds=[x for x in seeds_payload if isinstance(x, dict)],
            attacks=[x for x in attacks_payload if isinstance(x, dict)],
            session_events=[x for x in session_events if isinstance(x, dict)],
        )
        _json_response(self, normalize_bundle(bundle))

    def _serve_static(self, path: str) -> None:
        rel = "index.html" if path in {"/", ""} else path.lstrip("/")
        target = (FRONTEND_ROOT / rel).resolve()
        if FRONTEND_ROOT not in target.parents and target != FRONTEND_ROOT:
            self.send_error(HTTPStatus.FORBIDDEN)
            return
        if not target.exists() or target.is_dir():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        ctype, _ = mimetypes.guess_type(str(target))
        raw = target.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", (ctype or "application/octet-stream") + "; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        # Dev tooling — never cache HTML/JS/CSS so iterating on the viewer
        # actually shows up in the browser without a manual hard reload.
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.end_headers()
        self.wfile.write(raw)


def _default_bind_host() -> str:
    """127.0.0.1 on the host is fine; in Docker, bind 0.0.0.0 or port publishes never connect."""
    try:
        return "0.0.0.0" if Path("/.dockerenv").exists() else "127.0.0.1"
    except OSError:
        return "127.0.0.1"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Serve runtime-backed FragGuard viewer")
    parser.add_argument("--host", default=_default_bind_host())
    parser.add_argument("--port", type=int, default=8787)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    os.chdir(FRONTEND_ROOT)
    httpd = ThreadingHTTPServer((args.host, args.port), ViewerHandler)
    print(f"Serving FragGuard viewer at http://{args.host}:{args.port}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
