"""
JSON-lines logger for every LLM call (target, judge, generator).

Usage:
    from calllog import init_log, log_call

    init_log()  # creates log/<timestamp>.jsonl
    log_call(role="target", model="claude-sonnet-4-6", system=None,
             user="prompt text", output="response text", meta={...})
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_lock = threading.Lock()
_log_path: Path | None = None
_verbose: bool = False


def init_log(path: Path | None = None) -> Path:
    """Initialise the call log. Returns the log file path."""
    global _log_path
    if path is None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        path = Path("log") / f"{ts}.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    _log_path = path
    return _log_path


def set_verbose(enabled: bool) -> None:
    """Enable logging of non-target calls (judge, generator)."""
    global _verbose
    _verbose = enabled


def log_call(
    *,
    role: str,
    model: str,
    system: str | None = None,
    user: str,
    output: str,
    error: str | None = None,
    meta: dict[str, Any] | None = None,
) -> None:
    """Append one LLM call record to the log file."""
    if _log_path is None:
        return
    if role != "target" and not _verbose:
        return
    record: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "role": role,
        "model": model,
        "system": system,
        "user": user,
        "output": output,
    }
    if error:
        record["error"] = error
    if meta:
        record["meta"] = meta
    with _lock:
        with open(_log_path, "a") as f:
            f.write(json.dumps(record) + "\n")
