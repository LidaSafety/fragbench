#!/usr/bin/env -S uv run --python 3.11
"""
Unified MCP ↔ OpenRouter client with optional Jina integration and adaptive reasoning.

This single-file implementation consolidates the functionality of the prior
`mcp_openrouter_client*.py` variants into a dependency-light module that:

* Bridges MCP servers to OpenRouter-compatible models.
* Provides built-in tools for session management (terminal / Jupyter).
* Offers native Jina API tooling (embedding, search, read, rerank) without external helpers.
* Supports adaptive multi-turn tool calling with lightweight reasoning strategies.
* Records function calls to an optional SQLite database for auditing and analytics.

The goal is a maintainable, batteries-included client that can be dropped into any
project without importing auxiliary helpers from this repository.
"""

from __future__ import annotations

import argparse
import asyncio
import inspect
import logging
import json
import os
import signal
import sqlite3
import subprocess
import threading
import time
import uuid
import sys
import itertools
import textwrap
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import AsyncExitStack, suppress
from dataclasses import dataclass, field, asdict, is_dataclass
from datetime import datetime, timezone, date
from enum import Enum
from pathlib import Path
from queue import Empty, Queue
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib import error as urllib_error
from urllib import request as urllib_request
import shutil
import re
import base64

try:  # Optional dependency; fastmcp typically installs pydantic but guard just in case.
    from pydantic import BaseModel as PydanticBaseModel  # type: ignore
except Exception:  # pragma: no cover - pydantic not installed
    PydanticBaseModel = None  # type: ignore

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp_config_loader import MCPServerConfig, load_mcp_configs

# SSE transport for HTTP-based MCP servers (like tool registries)
try:
    from mcp.client.sse import sse_client
    SSE_AVAILABLE = True
except ImportError:
    sse_client = None  # type: ignore
    SSE_AVAILABLE = False

try:
    from mcp.client.streamable_http import streamablehttp_client
    STREAMABLE_HTTP_AVAILABLE = True
except ImportError:
    streamablehttp_client = None  # type: ignore
    STREAMABLE_HTTP_AVAILABLE = False
from openai import OpenAI

try:  # Optional experiential learning integration
    from experiential_learning_integration import LearningIntegration
except Exception:  # pragma: no cover - optional dependency
    LearningIntegration = None  # type: ignore[assignment]

try:  # Optional CLI slash command handler
    from cli_commands import integrate_cli_commands
except Exception:  # pragma: no cover - optional dependency
    integrate_cli_commands = None  # type: ignore[assignment]

try:  # Optional Tool Context Manager for RL training
    from tool_context_manager import ToolContextManager, LoadStrategy, EvictionPolicy
except Exception:  # pragma: no cover - optional dependency
    ToolContextManager = None  # type: ignore[assignment]
    LoadStrategy = None  # type: ignore[assignment]
    EvictionPolicy = None  # type: ignore[assignment]

RICH_AVAILABLE = True  # Simple stdout grid UI is always available
Console = None  # type: ignore
Group = None  # type: ignore
Panel = None  # type: ignore
Table = None  # type: ignore
Live = None  # type: ignore
Text = None  # type: ignore
box = None  # type: ignore


PROJECT_ROOT = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# Environment helpers
# ---------------------------------------------------------------------------

def _load_env_file(path: Optional[Path] = None) -> None:
    """
    Lightweight .env loader to avoid depending on python-dotenv.

    The function is intentionally simple: it strips comments, splits on the first
    equals sign, and populates os.environ if the key is not already set.
    """
    if "OPENROUTER_API_KEY" in os.environ and "JINA_API_KEY" in os.environ:
        # Fast exit when the most common variables are already present.
        return

    candidates: List[Path] = []

    if path is not None:
        candidates.append(Path(path).expanduser())
    else:
        default_env = (PROJECT_ROOT / ".env").expanduser()
        candidates.append(default_env)

        cwd_env = (Path.cwd() / ".env").expanduser()
        if cwd_env != default_env:
            candidates.append(cwd_env)

    for candidate in candidates:
        if not candidate.exists() or not candidate.is_file():
            continue

        for line in candidate.read_text().splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "=" not in stripped:
                continue
            key, value = stripped.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            os.environ.setdefault(key, value)


# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------

LOGS_DIR = PROJECT_ROOT / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOGS_DIR / f"mcp_client_v1_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("mcp_client_v1")


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _make_json_safe(value: Any, _visited: Optional[Set[int]] = None) -> Any:
    """
    Convert arbitrary Python objects (including pydantic/dataclass instances) into
    structures that json.dumps can handle.
    """
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")

    if _visited is None:
        _visited = set()
    obj_id = id(value)
    if obj_id in _visited:
        return "<recursion>"
    _visited.add(obj_id)
    try:
        if isinstance(value, dict):
            return {str(k): _make_json_safe(v, _visited) for k, v in value.items()}
        if isinstance(value, (list, tuple, set, frozenset)):
            return [_make_json_safe(item, _visited) for item in value]
        if is_dataclass(value):
            return _make_json_safe(asdict(value), _visited)
        if PydanticBaseModel is not None and isinstance(value, PydanticBaseModel):
            return _make_json_safe(value.model_dump(), _visited)
        if hasattr(value, "model_dump"):
            try:
                return _make_json_safe(value.model_dump(), _visited)
            except Exception:
                pass
        if hasattr(value, "dict"):
            try:
                return _make_json_safe(value.dict(), _visited)
            except Exception:
                pass
        if hasattr(value, "__dict__"):
            return {
                str(k): _make_json_safe(v, _visited)
                for k, v in vars(value).items()
                if not callable(v) and not k.startswith("_")
            }
        return str(value)
    finally:
        _visited.discard(obj_id)


def _json_dumps(value: Any, **kwargs: Any) -> str:
    """Dump Python objects to JSON using the json-safe conversion helper."""
    safe_value = _make_json_safe(value)
    try:
        return json.dumps(safe_value, **kwargs)
    except TypeError:
        # Last-resort fallback; safe_value should already be JSON-friendly but guard anyway.
        return json.dumps(str(safe_value), **kwargs)


def _coerce_to_json_text(value: Any) -> str:
    """Convert tool execution results into a printable string."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return _json_dumps(value, indent=2)
    except TypeError:
        return str(value)


def _truncate_text_to_tokens(text: str, max_tokens: int = 1024) -> str:
    """
    Truncate text to approximately max_tokens while preserving original spacing.

    We scan tokens lazily so large tool outputs do not require full parsing.
    """
    if not text:
        return ""
    if max_tokens <= 0:
        return ""

    token_matches = list(itertools.islice(re.finditer(r"\S+\s*", text), max_tokens + 1))
    if len(token_matches) <= max_tokens:
        return text

    truncated = "".join(match.group(0) for match in token_matches[:-1]).rstrip()
    return f"{truncated} ... [truncated]"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class ServerConfig:
    """Configuration required to launch an MCP server process."""

    command: str
    args: List[str] = field(default_factory=list)
    env: Optional[Dict[str, str]] = None


@dataclass
class SessionInfo:
    """Runtime information about an active shell or Jupyter session."""

    session_id: str
    session_type: str  # 'terminal' or 'jupyter'
    process: subprocess.Popen
    output_queue: Queue
    created_at: float
    last_activity: float




# Simple terminal colors using ANSI escape codes
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    BRIGHT_BLACK = '\033[90m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'


class RealtimeUI:
    """Simple grid-based streaming buffer replacing Rich UI."""

    def __init__(self, console=None):
        self.enabled = True
        self.width = min(shutil.get_terminal_size().columns, 120)
        self.buffer = []
        self.metrics = {
            'tokens': 0,
            'tokens_per_sec': 0.0,
            'cost': 0.0,
            'start_time': None,
            'last_update': None
        }
        self.tool_events = []
        self.current_status = ""
        self.query = ""
        self.iteration = 0
        self.max_iterations = 0
        self.state = {}
        self._active = False
        self.live = None  # Compatibility

    def _clear_line(self):
        """Clear current line."""
        sys.stdout.write('\r' + ' ' * self.width + '\r')
        sys.stdout.flush()

    def _print_status_line(self):
        """Print a simple status line."""
        if not self.enabled:
            return

        self._clear_line()

        # Build status line
        status_parts = []

        if self.query:
            truncated_query = self.query[:40] + "..." if len(self.query) > 40 else self.query
            status_parts.append(f"Query: {truncated_query}")

        if self.max_iterations > 0:
            status_parts.append(f"Iter: {self.iteration}/{self.max_iterations}")

        if self.metrics['tokens'] > 0:
            status_parts.append(f"Tokens: {self.metrics['tokens']}")

        if self.metrics['tokens_per_sec'] > 0:
            status_parts.append(f"Speed: {self.metrics['tokens_per_sec']:.1f} t/s")

        status_line = " | ".join(status_parts)
        sys.stdout.write(f"{Colors.CYAN}[{status_line}]{Colors.RESET}")
        sys.stdout.flush()

    def start(
        self,
        query: str,
        iterations: int = 6,
        strategy: str = "adaptive",
        *,
        iteration_budget: Optional[int] = None,
        model: str = "",
    ):
        """Start UI for a new query."""
        budget = iteration_budget if iteration_budget is not None else iterations
        if budget is None:
            budget = 0

        self.query = query
        self.max_iterations = budget
        self.iteration = 0
        self.buffer = []
        self.tool_events = []
        self.metrics['start_time'] = time.time()
        self.metrics['last_update'] = time.time()
        self.state = {
            "query": query,
            "iteration_budget": budget,
            "current_iteration": 0,
            "status": "waiting",
            "strategy": strategy,
            "streaming_buffer": [],
            "recent_fragments": [],
            "tool_events": [],
            "model": model,
        }
        self._active = True

        # Print header
        print(f"\n{Colors.BRIGHT_CYAN}{'=' * 80}{Colors.RESET}")
        print(f"{Colors.BRIGHT_GREEN}Processing query:{Colors.RESET} {query}")
        strategy_line = (
            f"{Colors.BRIGHT_YELLOW}Strategy:{Colors.RESET} {strategy} | "
            f"{Colors.BRIGHT_YELLOW}Max iterations:{Colors.RESET} {budget}"
        )
        if model:
            strategy_line += f" | {Colors.BRIGHT_YELLOW}Model:{Colors.RESET} {model}"
        print(strategy_line)
        print(f"{Colors.BRIGHT_CYAN}{'=' * 80}{Colors.RESET}\n")

        self._print_status_line()

    def update_iteration(self, iteration: int, status: str = None, detail: str = None):
        """Update iteration counter."""
        if not self.enabled:
            return
        self.iteration = iteration
        self.state["current_iteration"] = iteration
        if status:
            self.state["status"] = status
        if detail:
            self.state["detail"] = detail
        self._print_status_line()

    def update_streaming(self, text: str):
        """Update with streaming text."""
        if not self.enabled:
            return
        self.buffer.append(text)
        if "streaming_buffer" not in self.state:
            self.state["streaming_buffer"] = []
        self.state["streaming_buffer"].append(text)

        # Print the text inline
        sys.stdout.write(text)
        sys.stdout.flush()

        self.metrics['last_update'] = time.time()

    def append_assistant_fragment(self, fragment: str):
        """Compatibility helper used by streaming callbacks."""
        if not self.enabled or not fragment:
            return
        self.add_fragment(fragment)
        self.update_streaming(fragment)

    def add_fragment(self, fragment: str):
        """Add a text fragment."""
        if not self.enabled:
            return
        if "recent_fragments" not in self.state:
            self.state["recent_fragments"] = []
        self.state["recent_fragments"].append(fragment)

    def add_tool_event(self, event: str):
        """Add a tool event."""
        if not self.enabled:
            return
        self.tool_events.append(event)
        if "tool_events" not in self.state:
            self.state["tool_events"] = []
        self.state["tool_events"].append(event)

        # Print tool event on new line
        print(f"\n{Colors.YELLOW}[Tool]{Colors.RESET} {event}")
        self._print_status_line()

    def record_tool_event(self, name: str, success: bool, content: str):
        """Record structured tool events while preserving legacy API surface."""
        if not self.enabled:
            return
        summary = (content or "").strip()
        if summary:
            summary = _truncate_text_to_tokens(summary, max_tokens=64)
        status_symbol = "✓" if success else "✗"
        status_color = Colors.GREEN if success else Colors.RED
        decorated_event = f"{status_color}{status_symbol}{Colors.RESET} {name}"
        if summary:
            decorated_event += f" — {summary}"

        self.state.setdefault("tool_results", []).append({
            "name": name,
            "success": success,
            "content": summary
        })
        self.add_tool_event(decorated_event)

    def update_metrics(self, tokens: int = 0, cost: float = 0.0, tokens_per_sec: float = 0.0):
        """Update metrics."""
        if not self.enabled:
            return
        self.metrics['tokens'] = tokens
        self.metrics['cost'] = cost
        self.metrics['tokens_per_sec'] = tokens_per_sec
        self.state["metrics"] = {
            "tokens": tokens,
            "cost": cost,
            "tokens_per_sec": tokens_per_sec
        }
        self._print_status_line()

    def mark_error(self, message: str):
        """Display error state."""
        if not self.enabled:
            return
        self.state["status"] = "error"
        self.state["error"] = message
        print(f"\n{Colors.BRIGHT_RED}Error:{Colors.RESET} {message}\n")
        self._print_status_line()

    def finish(self, result: str, success: bool = True, iterations: int = 0):
        """Display final result while keeping compatibility with legacy calls."""
        if not self.enabled:
            return
        self.state["status"] = "complete" if success else "failed"
        self.state["final_response"] = result
        if result and not self.buffer:
            trimmed = result.strip()
            if trimmed:
                print(f"\n{Colors.BRIGHT_WHITE}{trimmed}{Colors.RESET}\n")
        self.complete(iterations, success=success)

    def complete(self, iterations: int, success: bool = True):
        """Mark completion."""
        if not self.enabled:
            return

        self._active = False
        print(f"\n\n{Colors.BRIGHT_GREEN}{'=' * 80}{Colors.RESET}")

        status = "✓ Complete" if success else "✗ Failed"
        print(f"{Colors.BRIGHT_GREEN if success else Colors.BRIGHT_RED}Status:{Colors.RESET} {status}")
        print(f"{Colors.BRIGHT_BLUE}Total iterations:{Colors.RESET} {iterations}")

        if self.metrics['tokens'] > 0:
            print(f"{Colors.BRIGHT_BLUE}Total tokens:{Colors.RESET} {self.metrics['tokens']}")
            print(f"{Colors.BRIGHT_BLUE}Total cost:{Colors.RESET} ${self.metrics['cost']:.6f}")

            if self.metrics['start_time']:
                elapsed = time.time() - self.metrics['start_time']
                print(f"{Colors.BRIGHT_BLUE}Time elapsed:{Colors.RESET} {elapsed:.1f}s")

        print(f"{Colors.BRIGHT_GREEN}{'=' * 80}{Colors.RESET}\n")

    def close(self):
        """Close the UI."""
        if not self.enabled:
            return
        self._active = False

    def _render(self):
        """Compatibility method."""
        return None

    def _stop_live(self):
        """Compatibility method."""
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class HookManager:
    """
    Lightweight event hook dispatcher inspired by the richer hook framework found
    in the Jina variants. Callbacks can be synchronous or asynchronous.
    """

    def __init__(self) -> None:
        self._hooks: Dict[str, List[Tuple[int, Callable[..., Any]]]] = {}

    def register(self, event: str, callback: Callable[..., Any], priority: int = 0) -> None:
        if not event or not callable(callback):
            raise ValueError("Hook registration requires a valid event name and callable.")
        self._hooks.setdefault(event, []).append((priority, callback))
        # Highest priority first
        self._hooks[event].sort(key=lambda entry: entry[0], reverse=True)

    def clear(self, event: Optional[str] = None) -> None:
        if event is None:
            self._hooks.clear()
        else:
            self._hooks.pop(event, None)

    async def dispatch(self, event: str, **payload: Any) -> Any:
        callbacks = self._hooks.get(event, [])
        if not callbacks:
            return None

        results: List[Any] = []
        for _, callback in callbacks:
            try:
                result = callback(**payload)
                if inspect.isawaitable(result):
                    result = await result  # type: ignore[assignment]
                if result is not None:
                    results.append(result)
            except Exception as exc:  # pragma: no cover - hook failures should not crash client
                logger.debug("Hook '%s' raised %s", event, exc, exc_info=True)
        if not results:
            return None
        if len(results) == 1:
            return results[0]
        return results


class ReasoningStrategy(Enum):
    """Strategies used to adapt the system message and temperature."""

    LINEAR = "linear"
    EXPLORATORY = "exploratory"
    COMPARATIVE = "comparative"
    CRITICAL = "critical"
    CREATIVE = "creative"
    SYSTEMATIC = "systematic"


@dataclass
class ReasoningThread:
    """Tracks the decision history for a single reasoning path."""

    thread_id: str
    strategy: ReasoningStrategy
    created_at: float = field(default_factory=time.time)
    depth: int = 0
    parent_id: Optional[str] = None
    context: List[Dict[str, Any]] = field(default_factory=list)
    decisions: List[Dict[str, Any]] = field(default_factory=list)
    children: List[str] = field(default_factory=list)
    confidence: float = 1.0

    def record_decision(self, decision_type: str, content: Any, rationale: str) -> None:
        self.decisions.append(
            {
                "type": decision_type,
                "content": content,
                "rationale": rationale,
                "timestamp": time.time(),
                "confidence": self.confidence,
            }
        )

    def branch(self, new_strategy: ReasoningStrategy) -> "ReasoningThread":
        child_id = str(uuid.uuid4())
        child = ReasoningThread(
            thread_id=child_id,
            strategy=new_strategy,
            created_at=time.time(),
            depth=self.depth + 1,
            parent_id=self.thread_id,
            confidence=max(0.3, self.confidence * 0.9),
        )
        self.children.append(child_id)
        return child


class SessionManager:
    """Handles long-running subprocesses for terminal and Jupyter sessions."""

    def __init__(self) -> None:
        self.sessions: Dict[str, SessionInfo] = {}
        self.executor = ThreadPoolExecutor(max_workers=8)
        self._lock = threading.Lock()

    def _stream_output(self, process: subprocess.Popen, output_queue: Queue, session_id: str) -> None:
        try:
            for line in iter(process.stdout.readline, b""):  # type: ignore[call-arg]
                if not line:
                    break
                decoded = line.decode("utf-8", errors="replace").rstrip("\n")
                output_queue.put(("stdout", decoded))
                with self._lock:
                    if session_id in self.sessions:
                        self.sessions[session_id].last_activity = time.time()

            for line in iter(process.stderr.readline, b""):  # type: ignore[call-arg]
                if not line:
                    break
                decoded = line.decode("utf-8", errors="replace").rstrip("\n")
                output_queue.put(("stderr", decoded))
                with self._lock:
                    if session_id in self.sessions:
                        self.sessions[session_id].last_activity = time.time()
        except Exception as exc:  # pragma: no cover - diagnostic helper
            output_queue.put(("error", f"Stream error: {exc}"))

    def _build_jupyter_command(
        self,
        notebook_path: Optional[str] = None,
        *,
        kernel_name: Optional[str] = None,
        packages: Optional[List[str]] = None,
        requirements: Optional[List[str]] = None,
        python: Optional[str] = None,
        extra_args: Optional[List[str]] = None,
        use_uv: bool = True,
    ) -> List[str]:
        def _normalize(items: Optional[Iterable[str]]) -> List[str]:
            if not items:
                return []
            result = []
            for item in items:
                if item is None:
                    continue
                stripped = str(item).strip()
                if stripped:
                    result.append(stripped)
            return result

        shared_args: List[str] = ["--simple-prompt"]
        if notebook_path:
            resolved = str(Path(notebook_path).expanduser())
            if not Path(resolved).exists():
                logger.warning("Notebook path '%s' does not exist; Jupyter may fail to attach.", resolved)
            shared_args.extend(["--existing", resolved])
        else:
            kernel = (kernel_name or "python3").strip()
            if kernel:
                shared_args.append(f"--kernel={kernel}")

        packages = _normalize(packages)
        requirements = _normalize(requirements)
        extra = _normalize(extra_args)

        uv_path = shutil.which("uv") if use_uv else None
        if uv_path:
            cmd = [uv_path, "tool", "run", "jupyter-console"]
            for pkg in packages:
                cmd.extend(["--with", pkg])
            for req in requirements:
                cmd.extend(["--with-requirements", req])
            if python:
                cmd.extend(["--python", python])
            cmd.append("--")
            cmd.extend(shared_args)
            cmd.extend(extra)
            return cmd

        if packages or requirements or python:
            raise RuntimeError("Specifying packages/requirements/python requires uv to be installed.")

        jupyter_console = shutil.which("jupyter-console")
        if jupyter_console:
            return [jupyter_console, *shared_args, *extra]

        jupyter = shutil.which("jupyter")
        if jupyter:
            return [jupyter, "console", *shared_args, *extra]

        ipython = shutil.which("ipython")
        if ipython:
            if notebook_path:
                logger.warning("IPython fallback does not support --existing; ignoring notebook path.")
            return [ipython, "--simple-prompt", *extra]

        raise RuntimeError("Unable to locate a Jupyter-compatible console.")

    def start_terminal_session(self, shell: str = "/bin/bash") -> str:
        session_id = str(uuid.uuid4())
        output_queue: Queue = Queue()
        process = subprocess.Popen(
            [shell],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
        info = SessionInfo(
            session_id=session_id,
            session_type="terminal",
            process=process,
            output_queue=output_queue,
            created_at=time.time(),
            last_activity=time.time(),
        )
        with self._lock:
            self.sessions[session_id] = info
        self.executor.submit(self._stream_output, process, output_queue, session_id)
        return session_id

    def start_jupyter_session(
        self,
        notebook_path: Optional[str] = None,
        packages: Optional[List[str]] = None,
        requirements: Optional[List[str]] = None,
        python: Optional[str] = None,
        extra_args: Optional[List[str]] = None,
        environment: Optional[Dict[str, str]] = None,
        kernel_name: Optional[str] = None,
        use_uv: bool = True,
        working_directory: Optional[str] = None,
    ) -> str:
        session_id = str(uuid.uuid4())
        output_queue: Queue = Queue()
        cmd = self._build_jupyter_command(
            notebook_path=notebook_path,
            kernel_name=kernel_name,
            packages=packages,
            requirements=requirements,
            python=python,
            extra_args=extra_args,
            use_uv=use_uv,
        )

        cwd = None
        if working_directory:
            resolved = Path(working_directory).expanduser()
            if not resolved.exists():
                raise RuntimeError(f"Working directory '{resolved}' does not exist.")
            cwd = str(resolved)

        env = dict(os.environ)
        env["PYTHONUNBUFFERED"] = "1"
        if environment:
            env.update({str(k): str(v) for k, v in environment.items()})

        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            cwd=cwd,
            env=env,
        )
        info = SessionInfo(
            session_id=session_id,
            session_type="jupyter",
            process=process,
            output_queue=output_queue,
            created_at=time.time(),
            last_activity=time.time(),
        )
        with self._lock:
            self.sessions[session_id] = info
        self.executor.submit(self._stream_output, process, output_queue, session_id)
        return session_id

    def send_to_session(self, session_id: str, command: str) -> bool:
        with self._lock:
            session = self.sessions.get(session_id)
        if not session:
            return False
        try:
            if session.process.poll() is not None:
                return False
            stdin = session.process.stdin
            if stdin is None:
                return False
            stdin.write((command + "\n").encode("utf-8"))
            stdin.flush()
            session.last_activity = time.time()
            return True
        except Exception:
            return False

    def get_session_output(self, session_id: str, timeout: float = 1.0) -> List[Tuple[str, str]]:
        with self._lock:
            session = self.sessions.get(session_id)
        if not session:
            return []

        output: List[Tuple[str, str]] = []
        end_time = time.time() + timeout
        while time.time() < end_time:
            try:
                output.append(session.output_queue.get_nowait())
            except Empty:
                time.sleep(0.05)
                if output:
                    break
        return output

    def list_sessions(self) -> List[Dict[str, Any]]:
        with self._lock:
            result = []
            for session_id, info in self.sessions.items():
                result.append(
                    {
                        "session_id": session_id,
                        "type": info.session_type,
                        "created_at": info.created_at,
                        "last_activity": info.last_activity,
                        "is_alive": info.process.poll() is None,
                    }
                )
        return result

    def kill_session(self, session_id: str) -> bool:
        with self._lock:
            info = self.sessions.get(session_id)
        if not info:
            return False

        try:
            if info.process.poll() is None:
                info.process.terminate()
                time.sleep(0.5)
                if info.process.poll() is None:
                    info.process.kill()
        finally:
            with self._lock:
                self.sessions.pop(session_id, None)
        return True

    def cleanup_dead_sessions(self) -> None:
        dead: List[str] = []
        with self._lock:
            for session_id, info in self.sessions.items():
                if info.process.poll() is not None:
                    dead.append(session_id)
            for session_id in dead:
                self.sessions.pop(session_id, None)

    def cleanup(self) -> None:
        for session_id in list(self.sessions.keys()):
            self.kill_session(session_id)
        self.executor.shutdown(wait=False)


# ---------------------------------------------------------------------------
# Jina integration without external dependencies
# ---------------------------------------------------------------------------


class JinaAPIError(RuntimeError):
    """Raised when the Jina API returns an error response."""


class JinaClient:
    """
    Minimal Jina API client implemented with urllib to avoid third-party dependencies.
    """

    BASE_URL = "https://api.jina.ai/v1"

    def __init__(self, api_key: Optional[str], timeout: float = 30.0) -> None:
        self.api_key = (api_key or "").strip()
        self.timeout = timeout

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    def _post(self, endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        if not self.enabled:
            raise RuntimeError("Jina API key not configured.")

        url = f"{self.BASE_URL}/{endpoint.lstrip('/')}"
        data = json.dumps(payload).encode("utf-8")
        request = urllib_request.Request(url, data=data, method="POST")
        request.add_header("Authorization", f"Bearer {self.api_key}")
        request.add_header("Content-Type", "application/json")
        try:
            with urllib_request.urlopen(request, timeout=self.timeout) as response:
                body = response.read().decode("utf-8")
                status = response.getcode()
        except urllib_error.HTTPError as exc:
            raise JinaAPIError(f"Jina API error {exc.code}: {exc.read().decode('utf-8', errors='replace')}") from exc
        except urllib_error.URLError as exc:
            raise JinaAPIError(f"Jina API request failed: {exc}") from exc

        if status >= 400:
            raise JinaAPIError(f"Jina API error {status}: {body}")
        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise JinaAPIError(f"Invalid JSON from Jina API: {exc}") from exc

    async def _embed_inputs(
        self,
        inputs: Sequence[str],
        *,
        model: str = "jina-embeddings-v4",
        **kwargs: Any,
    ) -> Dict[str, Any]:
        payload = {
            "model": model,
            "input": [text for text in inputs if isinstance(text, str) and text],
        }
        if not payload["input"]:
            return {"data": []}
        task = kwargs.get("task")
        if task:
            payload["task"] = task
        dimensions = kwargs.get("dimensions")
        if dimensions:
            payload["dimensions"] = int(dimensions)
        if "late_chunking" in kwargs:
            payload["late_chunking"] = bool(kwargs["late_chunking"])
        return await asyncio.to_thread(self._post, "embeddings", payload)

    async def embed(self, text: str, model: str = "jina-embeddings-v4", **kwargs: Any) -> Dict[str, Any]:
        return await self._embed_inputs([text], model=model, **kwargs)

    async def embed_batch(
        self,
        texts: Sequence[str],
        *,
        model: str = "jina-embeddings-v4",
        **kwargs: Any,
    ) -> Dict[str, Any]:
        return await self._embed_inputs(texts, model=model, **kwargs)

    async def rerank(
        self,
        query: str,
        documents: List[str],
        model: str = "jina-reranker-v2-base-multilingual",
        top_k: Optional[int] = None,
        return_documents: bool = True,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"model": model, "query": query, "documents": documents}
        if top_k is not None:
            payload["top_k"] = int(top_k)
        if return_documents is not None:
            payload["return_documents"] = bool(return_documents)
        return await asyncio.to_thread(self._post, "rerank", payload)

    async def read(
        self,
        url: str,
        *,
        format: str = "markdown",
        include_images: bool = True,
        include_links: bool = True,
        no_cache: bool = False,
        max_chars: int = 4000,
        store_full_content: bool = True,
    ) -> Dict[str, Any]:
        payload = {
            "url": url,
            "format": format,
            "include_images": include_images,
            "include_links": include_links,
            "no_cache": no_cache,
            "max_chars": max_chars,
            "store_full_content": store_full_content,
        }
        return await asyncio.to_thread(self._post, "reader", payload)

    async def search(
        self,
        query: str,
        *,
        search_type: str = "search",
        include_images: bool = False,
        include_links: bool = True,
        no_cache: bool = False,
        site: Optional[str] = None,
        country: Optional[str] = None,
        top_k: int = 5,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "query": query,
            "search_type": search_type,
            "include_images": include_images,
            "include_links": include_links,
            "no_cache": no_cache,
            "top_k": int(top_k),
        }
        if site:
            payload["site"] = site
        if country:
            payload["country"] = country
        return await asyncio.to_thread(self._post, "search", payload)


# ---------------------------------------------------------------------------
# MCP Client
# ---------------------------------------------------------------------------


@dataclass
class ToolIndex:
    """Lightweight tool index for retrieval."""
    name: str
    description: str
    server_name: Optional[str]
    is_builtin: bool
    embedding: Optional[List[float]] = None
    full_text: Optional[str] = None


class ToolRetriever:
    """Semantic tool retrieval using Jina embeddings."""

    def __init__(self, jina_client: Optional[Any] = None, use_embeddings: bool = True) -> None:
        self.tool_index: Dict[str, ToolIndex] = {}
        self.server_tools: Dict[str, List[str]] = {}
        self.jina = jina_client
        self.use_embeddings = use_embeddings and jina_client and jina_client.enabled
        self._embedding_cache: Dict[str, List[float]] = {}

    def index_tool(self, name: str, description: str, server_name: Optional[str] = None, is_builtin: bool = False) -> None:
        """Add tool to the index."""
        full_text = f"{name}: {description}"
        self.tool_index[name] = ToolIndex(
            name=name,
            description=description,
            server_name=server_name,
            is_builtin=is_builtin,
            embedding=None,  # Will be computed on first retrieval
            full_text=full_text
        )
        if server_name:
            self.server_tools.setdefault(server_name, []).append(name)

    async def _get_embedding(self, text: str) -> Optional[List[float]]:
        """Get embedding for text, with caching."""
        if not self.jina or not self.jina.enabled:
            return None

        if text in self._embedding_cache:
            return self._embedding_cache[text]

        try:
            response = await self.jina.embed(
                text=text,
                model="jina-embeddings-v4",
                task="retrieval.query" if len(text) < 200 else "retrieval.passage"
            )
            data = response.get("data", [])
            if data:
                embedding = data[0].get("embedding")
                if embedding:
                    self._embedding_cache[text] = embedding
                    return embedding
        except Exception as exc:
            logger.debug("Failed to get embedding: %s", exc)
        return None

    def _cosine_similarity(self, a: List[float], b: List[float]) -> float:
        """Compute cosine similarity between two vectors."""
        if not a or not b or len(a) != len(b):
            return 0.0
        dot = sum(x * y for x, y in zip(a, b))
        norm_a = sum(x * x for x in a) ** 0.5
        norm_b = sum(y * y for y in b) ** 0.5
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot / (norm_a * norm_b)

    def _keyword_score(self, query: str, tool_text: str) -> float:
        """Fallback keyword-based scoring."""
        query_words = set(re.findall(r'\b\w{3,}\b', query.lower()))
        tool_words = set(re.findall(r'\b\w{3,}\b', tool_text.lower()))
        if not query_words:
            return 0.0
        overlap = len(query_words & tool_words)
        return overlap / len(query_words)

    async def retrieve_relevant_tools(
        self,
        query: str,
        top_k: int = 20,
        threshold: float = 0.3,
        use_rerank: bool = False
    ) -> List[str]:
        """Retrieve tools relevant to the query using semantic search."""
        if not self.tool_index:
            return []

        builtin_tools = [name for name, info in self.tool_index.items() if info.is_builtin]

        # Try semantic retrieval first
        if self.use_embeddings:
            try:
                query_embedding = await self._get_embedding(query)
                if query_embedding:
                    return await self._semantic_retrieve(query, query_embedding, top_k, threshold, builtin_tools, use_rerank)
            except Exception as exc:
                logger.warning("Semantic retrieval failed, falling back to keywords: %s", exc)

        # Fallback to keyword-based retrieval
        return self._keyword_retrieve(query, top_k, threshold, builtin_tools)

    async def _semantic_retrieve(
        self,
        query: str,
        query_embedding: List[float],
        top_k: int,
        threshold: float,
        builtin_tools: List[str],
        use_rerank: bool
    ) -> List[str]:
        """Semantic retrieval using embeddings."""
        # Compute embeddings for all tools if not cached
        for tool_name, tool_info in self.tool_index.items():
            if tool_info.embedding is None and tool_info.full_text:
                tool_info.embedding = await self._get_embedding(tool_info.full_text)

        # Score tools by cosine similarity
        scored_tools: List[Tuple[str, float]] = []
        for tool_name, tool_info in self.tool_index.items():
            if tool_info.embedding:
                score = self._cosine_similarity(query_embedding, tool_info.embedding)
                if score >= threshold or tool_info.is_builtin:
                    scored_tools.append((tool_name, score))

        # Sort by score
        scored_tools.sort(key=lambda x: x[1], reverse=True)

        # Take top candidates
        candidates = [name for name, _ in scored_tools[:min(top_k * 2, len(scored_tools))]]

        # Optional reranking
        if use_rerank and self.jina and self.jina.enabled and len(candidates) > top_k:
            try:
                candidates = await self._rerank_tools(query, candidates, top_k)
            except Exception as exc:
                logger.debug("Reranking failed: %s", exc)

        # Ensure builtins are included
        result = []
        for name in candidates[:top_k]:
            if name not in result:
                result.append(name)
        for bt in builtin_tools:
            if bt not in result:
                result.append(bt)

        return result[:top_k]

    def _keyword_retrieve(self, query: str, top_k: int, threshold: float, builtin_tools: List[str]) -> List[str]:
        """Fallback keyword-based retrieval."""
        scored_tools: List[Tuple[str, float]] = []
        for tool_name, tool_info in self.tool_index.items():
            score = self._keyword_score(query, tool_info.full_text or "")
            if score >= threshold or tool_info.is_builtin:
                scored_tools.append((tool_name, score))

        scored_tools.sort(key=lambda x: x[1], reverse=True)
        result = [name for name, _ in scored_tools[:top_k]]

        # Ensure builtins
        for bt in builtin_tools:
            if bt not in result:
                result.append(bt)

        return result[:top_k]

    async def _rerank_tools(self, query: str, tool_names: List[str], top_k: int) -> List[str]:
        """Rerank tools using Jina reranker."""
        if not self.jina or not tool_names:
            return tool_names[:top_k]

        # Build documents for reranking
        documents = []
        name_map = {}
        for i, name in enumerate(tool_names):
            if name in self.tool_index:
                tool = self.tool_index[name]
                doc_text = f"{tool.name}: {tool.description}"
                documents.append(doc_text)
                name_map[i] = name

        if not documents:
            return tool_names[:top_k]

        # Rerank
        response = await self.jina.rerank(
            query=query,
            documents=documents,
            model="jina-reranker-v2-base-multilingual",
            top_k=top_k,
            return_documents=False
        )

        # Extract reranked names
        results = response.get("results", [])
        reranked_names = []
        for result in results:
            idx = result.get("index")
            if idx is not None and idx in name_map:
                reranked_names.append(name_map[idx])

        return reranked_names

    def get_servers_for_tools(self, tool_names: List[str]) -> Set[str]:
        """Get the set of servers needed for the given tools."""
        servers = set()
        for name in tool_names:
            if name in self.tool_index and self.tool_index[name].server_name:
                servers.add(self.tool_index[name].server_name)
        return servers


class MCPOpenRouterClientV1:
    """Unified client encapsulating MCP orchestration and OpenRouter interactions."""

    def __init__(
        self,
        *,
        model: str = "anthropic/claude-sonnet-4.5",
        base_url: str = "https://openrouter.ai/api/v1",
        system_prompt: Optional[str] = None,
        capabilities: Optional[Iterable[str]] = None,
        allowed_tools: Optional[Iterable[str]] = None,
        blocked_tools: Optional[Iterable[str]] = None,
        delegation_enabled: Optional[bool] = None,
        routing_enabled: Optional[bool] = None,
        mutation_enabled: Optional[bool] = None,
        database_path: Optional[Path] = None,
        default_max_iterations: int = 30,
        temperature: float = 1.0,
        max_tokens: int = 6500,
        parallel_tools: bool = True,
        multi_turn_enabled: bool = True,
        enable_jina: bool = True,
        enable_tool_retrieval: bool = True,
        tool_retrieval_top_k: int = 40,
        enable_middle_out: bool = True,
        enable_tool_reranking: bool = False,
        semantic_retrieval_threshold: float = 0.12345,
        # Tool Context Manager configuration
        enable_tool_context_manager: bool = True,
        max_loaded_tools: int = 35,
        tool_load_strategy: str = "semantic",  # immediate, lazy, semantic, learned
        tool_eviction_policy: str = "cost_aware",  # lru, lfu, cost_aware, learned
        enable_rl_tracking: bool = True,
        mcp_only: bool = False,
    ) -> None:
        self.model = model
        self.base_url = base_url
        self.system_prompt = system_prompt.strip() if system_prompt else None
        self.capabilities: Set[str] = {cap.strip().lower() for cap in capabilities or [] if cap.strip()}

        def _normalize_optional(iterable: Optional[Iterable[str]]) -> Optional[Set[str]]:
            if not iterable:
                return None
            values = {item.strip().lower() for item in iterable if item and item.strip()}
            return values or None

        self.allowed_tool_names = _normalize_optional(allowed_tools)
        self.blocked_tool_names = _normalize_optional(blocked_tools) or set()
        self.delegation_enabled = self._resolve_capability_flag("delegation", delegation_enabled)
        self.routing_enabled = self._resolve_capability_flag("routing", routing_enabled)
        self.mutation_enabled = self._resolve_capability_flag("mutation", mutation_enabled)

        self.temperature = temperature
        self.max_tokens = max_tokens
        self.default_max_iterations = default_max_iterations
        self.parallel_tools = parallel_tools
        self.multi_turn_enabled = multi_turn_enabled
        self.enable_tool_retrieval = enable_tool_retrieval
        self.tool_retrieval_top_k = tool_retrieval_top_k
        self.enable_middle_out = enable_middle_out
        self.enable_tool_reranking = enable_tool_reranking
        self.semantic_retrieval_threshold = semantic_retrieval_threshold
        self.enable_tool_context_manager = enable_tool_context_manager and ToolContextManager is not None
        self.max_loaded_tools = max_loaded_tools
        self.enable_rl_tracking = enable_rl_tracking
        self.mcp_only = mcp_only

        self.jina = JinaClient(os.getenv("JINA_API_KEY") if enable_jina else None)
        self.session_manager = SessionManager()
        self.native_tool_schemas: List[Dict[str, Any]] = []
        self.native_tool_executors: Dict[str, Callable[[Dict[str, Any]], Awaitable[str]]] = {}
        self.native_tool_groups: Dict[str, List[str]] = {}
        self.mcp_sessions: Dict[str, ClientSession] = {}
        self.mcp_tool_registry: Dict[str, Tuple[str, str]] = {}
        self.mcp_tool_schemas: List[Dict[str, Any]] = []
        self.mcp_tools_by_server: Dict[str, List[str]] = {}

        # Initialize Tool Context Manager or fallback to basic retriever
        self.tool_context: Optional[Any] = None
        self.tool_retriever: Optional[Any] = None

        if self.enable_tool_context_manager and ToolContextManager:
            # Use advanced Tool Context Manager for RL training and dynamic management
            load_strategy = LoadStrategy.SEMANTIC
            eviction_policy = EvictionPolicy.COST_AWARE

            # Map string to enum
            if tool_load_strategy == "immediate":
                load_strategy = LoadStrategy.IMMEDIATE
            elif tool_load_strategy == "lazy":
                load_strategy = LoadStrategy.LAZY
            elif tool_load_strategy == "learned":
                load_strategy = LoadStrategy.LEARNED

            if tool_eviction_policy == "lru":
                eviction_policy = EvictionPolicy.LRU
            elif tool_eviction_policy == "lfu":
                eviction_policy = EvictionPolicy.LFU
            elif tool_eviction_policy == "learned":
                eviction_policy = EvictionPolicy.LEARNED

            self.tool_context = ToolContextManager(
                max_loaded_tools=self.max_loaded_tools,
                load_strategy=load_strategy,
                eviction_policy=eviction_policy,
                jina_client=self.jina,
                enable_rl_tracking=self.enable_rl_tracking
            )
            logger.info("Tool Context Manager initialized with %s loading and %s eviction",
                       tool_load_strategy, tool_eviction_policy)
        else:
            # Fallback to basic tool retriever
            self.tool_retriever = ToolRetriever(jina_client=self.jina, use_embeddings=enable_jina)
            logger.info("Using basic tool retriever (Tool Context Manager unavailable)")

        if not self.mcp_only:
            self._setup_native_tools()
            self._index_builtin_tools()

        self.learning: Optional[Any] = None
        if LearningIntegration:
            try:
                self.learning = LearningIntegration(self)
            except Exception as exc:
                logger.debug("Experiential learning unavailable: %s", exc)

        self.session: Optional[ClientSession] = None
        self.exit_stack = AsyncExitStack()
        self.messages: List[Dict[str, Any]] = []
        self.function_call_history: List[Dict[str, Any]] = []
        self.enable_logging = True
        self.verbose_mode = True

        self.hooks = HookManager()
        self.reasoning_threads: Dict[str, ReasoningThread] = {}
        self.active_thread_id: Optional[str] = None
        self.iteration_history: deque = deque(maxlen=50)

        self.session_id = str(uuid.uuid4())
        self.database_path = Path(database_path).expanduser() if database_path else None
        self._db_connection: Optional[sqlite3.Connection] = None
        if self.database_path:
            self._init_database()

        self.openai = OpenAI(
            api_key=os.getenv("OPENROUTER_API_KEY"),
            base_url=base_url,
            max_retries=3  # Add retry mechanism for resilience
        )

        # Image handling configuration/state
        self._images_dir: Path = (Path.cwd() / "images").resolve()
        try:
            self._images_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            # Fallback to project root if CWD fails
            self._images_dir = (PROJECT_ROOT / "images").resolve()
            self._images_dir.mkdir(parents=True, exist_ok=True)
        self._last_saved_images: List[str] = []
        self._inline_image_viewer: Optional[Tuple[str, Tuple[str, ...]]] = None

    # ------------------------------------------------------------------
    # Setup helpers
    # ------------------------------------------------------------------

    def _resolve_capability_flag(self, capability_name: str, explicit: Optional[bool]) -> bool:
        if explicit is not None:
            return explicit
        if self.capabilities:
            return capability_name.lower() in self.capabilities
        return True

    def _init_database(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.database_path)
        self._db_connection = conn
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                started_at TEXT NOT NULL,
                system_prompt TEXT,
                capabilities TEXT
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS function_calls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                iteration INTEGER,
                tool_name TEXT NOT NULL,
                success INTEGER NOT NULL,
                arguments TEXT,
                result TEXT,
                latency REAL
            )
            """
        )
        cursor.execute(
            """
            INSERT OR IGNORE INTO sessions(session_id, started_at, system_prompt, capabilities)
            VALUES (?, ?, ?, ?)
            """,
            (
                self.session_id,
                datetime.now(timezone.utc).isoformat(),
                self.system_prompt or "",
                json.dumps(sorted(self.capabilities)),
            ),
        )
        conn.commit()

    # ------------------------------------------------------------------
    # Image utilities (save, inline render, content extraction)
    # ------------------------------------------------------------------

    def _detect_image_viewer(self) -> Optional[Tuple[str, Tuple[str, ...]]]:
        """Detect an available terminal image viewer for inline display."""
        if self._inline_image_viewer is not None:
            return self._inline_image_viewer
        # Prefer imgcat if available (iTerm2)
        if shutil.which("imgcat"):
            self._inline_image_viewer = ("imgcat", ("imgcat",))
            return self._inline_image_viewer
        # WezTerm
        if shutil.which("wezterm"):
            self._inline_image_viewer = ("wezterm", ("wezterm", "imgcat"))
            return self._inline_image_viewer
        # Kitty
        if shutil.which("kitty"):
            self._inline_image_viewer = ("kitty", ("kitty", "+kitten", "icat"))
            return self._inline_image_viewer
        self._inline_image_viewer = None
        return None

    def _try_inline_image_display(self, image_path: str) -> bool:
        """Attempt to display an image file inline in supported terminals."""
        viewer = self._detect_image_viewer()
        if not viewer or not image_path:
            return False
        method, cmd = viewer
        try:
            subprocess.run((*cmd, image_path), check=False)
            # Ensure newline for cleanliness
            sys.stdout.flush()
            print("")
            return True
        except Exception:
            return False

    def _save_image_bytes(self, data: bytes, ext: str = "png") -> str:
        """Persist image bytes to disk and register as an attachment. Returns path."""
        safe_ext = ext.lower().replace("jpeg", "jpg")
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        fname = f"image_{ts}_{uuid.uuid4().hex[:8]}.{safe_ext}"
        path = (self._images_dir / fname).resolve()
        with open(path, "wb") as f:
            f.write(data)
        self._last_saved_images.append(str(path))
        # Register with attachment manager (best-effort)
        try:
            from file_attachment_tools import get_file_manager  # lazy import
            get_file_manager().add_file(str(path))
        except Exception:
            pass
        return str(path)

    def _extract_and_save_images_from_text(self, content: str) -> Tuple[str, List[str]]:
        """
        Detect embedded base64 images (data URLs or raw PNG/JPEG/GIF headers),
        save them to disk, and replace with a short placeholder in the content.
        Returns: (cleaned_text, saved_paths)
        """
        saved: List[str] = []
        cleaned = content

        # 1) Data URLs
        data_url_pattern = re.compile(r"data:image/(png|jpeg|jpg|gif);base64,([A-Za-z0-9+/=\r\n]+)", re.IGNORECASE)
        while True:
            m = data_url_pattern.search(cleaned)
            if not m:
                break
            ext = m.group(1).lower().replace("jpeg", "jpg")
            b64 = m.group(2)
            try:
                data = base64.b64decode(re.sub(r"[^A-Za-z0-9+/=]", "", b64), validate=False)
                saved_path = self._save_image_bytes(data, ext)
                saved.append(saved_path)
                placeholder = f"[Saved image → {saved_path}]"
                cleaned = cleaned[:m.start()] + placeholder + cleaned[m.end():]
            except Exception:
                # If decode fails, remove the data URL header to avoid token bloat
                cleaned = cleaned[:m.start()] + "[image omitted]" + cleaned[m.end():]

        # 2) Raw base64 headers for PNG/JPEG/GIF, very long sequences
        raw_patterns = [
            (re.compile(r"iVBORw0KGgo[0-9A-Za-z+/=]{800,}"), "png"),
            (re.compile(r"/9j/[0-9A-Za-z+/=]{800,}"), "jpg"),
            (re.compile(r"R0lGODdh[0-9A-Za-z+/=]{800,}"), "gif"),
            (re.compile(r"R0lGODlh[0-9A-Za-z+/=]{800,}"), "gif"),
        ]

        # Limit to avoid pathological cases
        max_found = 4
        found_any = True
        while found_any and max_found > 0:
            found_any = False
            for pat, ext in raw_patterns:
                m2 = pat.search(cleaned)
                if not m2:
                    continue
                found_any = True
                b64 = m2.group(0)
                try:
                    data = base64.b64decode(re.sub(r"[^A-Za-z0-9+/=]", "", b64), validate=False)
                    saved_path = self._save_image_bytes(data, ext)
                    saved.append(saved_path)
                    placeholder = f"[Saved image → {saved_path}]"
                    cleaned = cleaned[:m2.start()] + placeholder + cleaned[m2.end():]
                except Exception:
                    cleaned = cleaned[:m2.start()] + "[image omitted]" + cleaned[m2.end():]
                max_found -= 1
                if max_found <= 0:
                    break

        return cleaned, saved

    def _build_user_message_with_pinned_images(self, query: str) -> Dict[str, Any]:
        """Build a user message that includes pinned image attachments as image parts.

        Only includes a small number of pinned images (up to 2) to avoid bloat.
        """
        try:
            from file_attachment_tools import get_file_manager  # lazy import
            manager = get_file_manager()
            pinned_images = [
                att for att in manager.attachments.values()
                if att.get("pinned") and str(att.get("mime_type", "")).startswith("image/") and att.get("base64")
            ]
        except Exception:
            pinned_images = []

        if not pinned_images:
            return {"role": "user", "content": query}

        parts: List[Dict[str, Any]] = []
        if query.strip():
            # Prefer OpenAI-style part for text
            parts.append({"type": "text", "text": query})

        # Cap number of images and aggregate size
        total_chars = 0
        max_images = 2
        for att in pinned_images[:max_images]:
            mime = att.get("mime_type", "image/png")
            b64 = att.get("base64", "")
            total_chars += len(b64)
            if total_chars > 2_000_000:  # ~2MB base64 cap for safety
                break
            url = f"data:{mime};base64,{b64}"
            parts.append({"type": "image_url", "image_url": {"url": url}})

        return {"role": "user", "content": parts if parts else query}

    def _record_function_call_to_db(self, data: Dict[str, Any]) -> None:
        if not self._db_connection:
            return
        cursor = self._db_connection.cursor()
        cursor.execute(
            """
            INSERT INTO function_calls(session_id, timestamp, iteration, tool_name, success, arguments, result, latency)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                self.session_id,
                datetime.now(timezone.utc).isoformat(),
                data.get("iteration"),
                data.get("tool_name"),
                1 if data.get("success") else 0,
                _json_dumps(data.get("arguments")),
                data.get("result"),
                float(data.get("latency", 0)),
            ),
        )
        self._db_connection.commit()

    def _log_function_call(self, tool_name: str, arguments: Dict[str, Any], result: str, success: bool, iteration: int, latency: float) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool_name": tool_name,
            "arguments": arguments,
            "result": result,
            "success": success,
            "iteration": iteration,
            "latency": latency,
        }
        self.function_call_history.append(entry)
        if self.enable_logging:
            status = "SUCCESS" if success else "ERROR"
            args_preview = _json_dumps(arguments)[:300]
            result_preview = result if isinstance(result, str) else _coerce_to_json_text(result)
            logger.info("Tool %s [%s] args=%s result=%s", tool_name, status, args_preview, result_preview[:200])
        self._record_function_call_to_db(entry)

    # ------------------------------------------------------------------
    # Native tool registry
    # ------------------------------------------------------------------

    def _setup_native_tools(self) -> None:
        """Attempt to register native tool packs that are available in the environment."""
        self.native_tool_schemas.clear()
        self.native_tool_executors.clear()
        self.native_tool_groups.clear()

        def register_pack(
            pack_name: str,
            loader: Callable[[], List[Dict[str, Any]]],
            runner: Callable[[str, Dict[str, Any]], Awaitable[Any]],
        ) -> None:
            try:
                schemas = loader()
            except Exception as exc:  # pragma: no cover - optional dependency
                logger.debug("Skipping %s tools (schema load failed): %s", pack_name, exc)
                return
            if not schemas:
                return
            self._register_native_tool_pack(pack_name, schemas, runner)

        try:
            from kb_mcp_tools import get_kb_mcp_tool_schemas, execute_kb_tool
        except Exception as exc:
            logger.debug("Knowledge base tools unavailable: %s", exc)
        else:
            async def kb_runner(tool_name: str, arguments: Dict[str, Any]) -> Any:
                return await execute_kb_tool(tool_name, arguments)
            register_pack("knowledge_base", get_kb_mcp_tool_schemas, kb_runner)

        try:
            from arxiv_mcp_tools import get_arxiv_mcp_tool_schemas, execute_arxiv_tool
        except Exception as exc:
            logger.debug("ArXiv tools unavailable: %s", exc)
        else:
            async def arxiv_runner(tool_name: str, arguments: Dict[str, Any]) -> Any:
                return await execute_arxiv_tool(tool_name, arguments)
            register_pack("arxiv", get_arxiv_mcp_tool_schemas, arxiv_runner)

        try:
            from file_ingestion_tools import get_file_ingestion_tool_schemas, execute_file_ingestion_tool
        except Exception as exc:
            logger.debug("File ingestion tools unavailable: %s", exc)
        else:
            async def ingestion_runner(tool_name: str, arguments: Dict[str, Any]) -> Any:
                return await execute_file_ingestion_tool(tool_name, arguments)
            register_pack("file_ingestion", get_file_ingestion_tool_schemas, ingestion_runner)

        try:
            from advanced_pdf_ingestion import get_advanced_pdf_tool_schemas, execute_advanced_pdf_tool
        except Exception as exc:
            logger.debug("Advanced PDF tools unavailable: %s", exc)
        else:
            async def advanced_pdf_runner(tool_name: str, arguments: Dict[str, Any]) -> Any:
                return await execute_advanced_pdf_tool(tool_name, arguments)
            register_pack("advanced_pdf", get_advanced_pdf_tool_schemas, advanced_pdf_runner)

        try:
            from context_grid_tools import get_context_grid_tool_schemas, execute_context_grid_tool
        except Exception as exc:
            logger.debug("Context grid tools unavailable: %s", exc)
        else:
            async def context_runner(tool_name: str, arguments: Dict[str, Any]) -> Any:
                return await asyncio.to_thread(
                    execute_context_grid_tool,
                    tool_name,
                    arguments,
                    self.system_prompt,
                )
            register_pack("context_grid", get_context_grid_tool_schemas, context_runner)

        try:
            from hierarchical_mutation_tools import get_hierarchical_mutation_tool_schemas, execute_hierarchical_mutation_tool
        except Exception as exc:
            logger.debug("Hierarchical mutation tools unavailable: %s", exc)
        else:
            async def mutation_runner(tool_name: str, arguments: Dict[str, Any]) -> Any:
                return await execute_hierarchical_mutation_tool(tool_name, arguments)
            register_pack("hierarchical_mutation", get_hierarchical_mutation_tool_schemas, mutation_runner)

        try:
            from advanced_weather_tool import get_advanced_weather_tool_schemas, execute_advanced_weather_tool
        except Exception as exc:
            logger.debug("Advanced weather tools unavailable: %s", exc)
        else:
            async def weather_runner(tool_name: str, arguments: Dict[str, Any]) -> Any:
                return await execute_advanced_weather_tool(tool_name, arguments)
            register_pack("advanced_weather", get_advanced_weather_tool_schemas, weather_runner)

        # Geopolitics tools
        try:
            from geopolitics_mcp_tools import get_geopolitics_mcp_tool_schemas, execute_geopolitics_tool
        except Exception as exc:
            logger.debug("Geopolitics tools unavailable: %s", exc)
        else:
            async def geop_runner(tool_name: str, arguments: Dict[str, Any]) -> Any:
                return await execute_geopolitics_tool(tool_name, arguments)
            register_pack("geopolitics", get_geopolitics_mcp_tool_schemas, geop_runner)

        try:
            from file_attachment_tools import get_file_attachment_tool_schemas, execute_file_attachment_tool
        except Exception as exc:
            logger.debug("File attachment tools unavailable: %s", exc)
        else:
            async def attachment_runner(tool_name: str, arguments: Dict[str, Any]) -> Any:
                return await asyncio.to_thread(execute_file_attachment_tool, tool_name, arguments)
            register_pack("file_attachments", get_file_attachment_tool_schemas, attachment_runner)

        try:
            from vision_mcp_tools import get_vision_tool_schemas, execute_vision_tool
        except Exception as exc:
            logger.debug("Vision tools unavailable: %s", exc)
        else:
            async def vision_runner(tool_name: str, arguments: Dict[str, Any]) -> Any:
                return await execute_vision_tool(self, tool_name, arguments)
            register_pack("vision", get_vision_tool_schemas, vision_runner)

    def _register_native_tool_pack(
        self,
        pack_name: str,
        schemas: List[Dict[str, Any]],
        runner: Callable[[str, Dict[str, Any]], Awaitable[Any]],
    ) -> None:
        tool_names: List[str] = []
        for schema in schemas:
            tool_name = schema.get("function", {}).get("name")
            if not tool_name:
                continue

            async def executor(arguments: Dict[str, Any], _tool=tool_name, _runner=runner) -> str:
                try:
                    result = _runner(_tool, arguments)
                    if inspect.isawaitable(result):
                        result = await result
                    return _coerce_to_json_text(result)
                except Exception as exc:
                    raise RuntimeError(f"{_tool} failed: {exc}") from exc

            self.native_tool_executors[tool_name] = executor
            self.native_tool_schemas.append(schema)
            tool_names.append(tool_name)

            # Register/index the tool
            description = schema.get("function", {}).get("description", "")
            if self.tool_context:
                # Register with Tool Context Manager
                self.tool_context.register_tool(
                    name=tool_name,
                    schema=schema,
                    server_name=None,
                    is_builtin=False,
                    auto_load=False  # Native tools loaded on demand
                )
            elif self.tool_retriever:
                # Index with basic retriever
                self.tool_retriever.index_tool(tool_name, description, server_name=None, is_builtin=False)

        if tool_names:
            self.native_tool_groups[pack_name] = tool_names
            logger.debug("Registered %d native tools for pack '%s'.", len(tool_names), pack_name)

    def _index_builtin_tools(self) -> None:
        """Index/register builtin tools for retrieval."""
        builtin_tools = self._builtin_session_tools() + self._builtin_python_tools() + self._builtin_jina_tools()
        for schema in builtin_tools:
            name = schema.get("function", {}).get("name")
            description = schema.get("function", {}).get("description", "")
            if name:
                if self.tool_context:
                    # Register with Tool Context Manager
                    self.tool_context.register_tool(
                        name=name,
                        schema=schema,
                        server_name=None,
                        is_builtin=True,
                        auto_load=True  # Builtins always loaded
                    )
                elif self.tool_retriever:
                    # Index with basic retriever
                    self.tool_retriever.index_tool(name, description, server_name=None, is_builtin=True)

    def _run_python_snippet(
        self,
        code: str,
        *,
        python: Optional[str] = None,
        timeout: float = 30.0,
        working_directory: Optional[str] = None,
        environment: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if not code or not code.strip():
            raise ValueError("Python code cannot be empty.")
        python_exec = python or os.environ.get("PYTHON") or sys.executable or shutil.which("python3") or shutil.which("python")
        if not python_exec:
            raise RuntimeError("Unable to locate a Python interpreter.")

        env = dict(os.environ)
        if environment:
            env.update({str(k): str(v) for k, v in environment.items()})

        cwd = None
        if working_directory:
            resolved = Path(working_directory).expanduser()
            if not resolved.exists():
                raise RuntimeError(f"Working directory '{resolved}' does not exist.")
            cwd = str(resolved)

        try:
            completed = subprocess.run(
                [python_exec, "-c", code],
                capture_output=True,
                text=True,
                timeout=float(timeout),
                cwd=cwd,
                env=env,
            )
        except subprocess.TimeoutExpired as exc:
            return {
                "returncode": None,
                "stdout": exc.stdout or "",
                "stderr": ((exc.stderr or "") + f"\nTimed out after {timeout:.1f}s").strip(),
                "timeout": True,
            }

        return {
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "timeout": False,
        }

    # ------------------------------------------------------------------
    # MCP connection management
    # ------------------------------------------------------------------

    async def connect_to_server(self, server: ServerConfig, server_name: Optional[str] = None) -> str:
        """
        Connect to an MCP server and register its tools.

        Returns:
            Resolved server name used for namespacing tools.
        """
        if isinstance(server, dict):
            command = server.get("command")
            args = list(server.get("args", []))
            env = server.get("env")
            name_hint = server.get("name")
        else:
            command = getattr(server, "command", None)
            args = list(getattr(server, "args", []))
            env = getattr(server, "env", None)
            name_hint = getattr(server, "name", None)

        resolved_name = self._derive_server_name(server_name or name_hint, command, args)
        params = StdioServerParameters(command=command, args=args, env=env)

        try:
            read_stream, write_stream = await self.exit_stack.enter_async_context(stdio_client(params))
            session = await self.exit_stack.enter_async_context(ClientSession(read_stream, write_stream))
            await session.initialize()
        except Exception as exc:
            logger.error("Failed to connect to MCP server %s", resolved_name)
            raise

        self.mcp_sessions[resolved_name] = session
        if not self.session:
            self.session = session

        await self._register_mcp_tools_for_session(resolved_name, session)
        logger.info("Connected to MCP server '%s' (%s %s)", resolved_name, command, " ".join(args))
        return resolved_name

    async def connect_to_http_server(
        self,
        url: str,
        server_name: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> str:
        """
        Connect to an HTTP/SSE MCP server (like tools.distributed.systems).

        Args:
            url: The SSE endpoint URL (e.g., "https://tools.distributed.systems/mcp/sse")
            server_name: Optional name for the server (defaults to hostname)

        Returns:
            Resolved server name used for namespacing tools.
        """
        if not SSE_AVAILABLE:
            raise RuntimeError("SSE client not available. Install mcp[sse] or upgrade mcp package.")

        # Derive server name from URL if not provided
        if not server_name:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            server_name = parsed.netloc.replace(".", "_").replace(":", "_") or "http_mcp"

        resolved_name = self._derive_server_name(server_name, None, [])

        try:
            # Connect via SSE transport
            read_stream, write_stream = await self.exit_stack.enter_async_context(
                sse_client(url, headers=headers)
            )
            session = await self.exit_stack.enter_async_context(ClientSession(read_stream, write_stream))
            await session.initialize()
        except Exception as exc:
            logger.error("Failed to connect to HTTP MCP server %s at %s: %s", resolved_name, url, exc)
            raise

        self.mcp_sessions[resolved_name] = session
        if not self.session:
            self.session = session

        await self._register_mcp_tools_for_session(resolved_name, session)
        logger.info("Connected to HTTP MCP server '%s' at %s", resolved_name, url)
        return resolved_name

    async def connect_to_streamable_http_server(
        self,
        url: str,
        server_name: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> str:
        """
        Connect to a Streamable HTTP MCP server.

        Args:
            url: The Streamable HTTP endpoint URL (for example, "http://127.0.0.1:8001/mcp")
            server_name: Optional name for the server (defaults to hostname)
            headers: Optional HTTP headers for authentication or routing

        Returns:
            Resolved server name used for namespacing tools.
        """
        if not STREAMABLE_HTTP_AVAILABLE:
            raise RuntimeError(
                "Streamable HTTP client not available. Install a newer mcp package with streamable_http support."
            )

        if not server_name:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            server_name = parsed.netloc.replace(".", "_").replace(":", "_") or "streamable_http_mcp"

        resolved_name = self._derive_server_name(server_name, None, [])

        try:
            read_stream, write_stream, _get_session_id = await self.exit_stack.enter_async_context(
                streamablehttp_client(url, headers=headers)
            )
            session = await self.exit_stack.enter_async_context(ClientSession(read_stream, write_stream))
            await session.initialize()
        except Exception as exc:
            logger.error("Failed to connect to Streamable HTTP MCP server %s at %s: %s", resolved_name, url, exc)
            raise

        self.mcp_sessions[resolved_name] = session
        if not self.session:
            self.session = session

        await self._register_mcp_tools_for_session(resolved_name, session)
        logger.info("Connected to Streamable HTTP MCP server '%s' at %s", resolved_name, url)
        return resolved_name

    async def connect_to_tool_registry(self, registry_url: str = "https://tools.distributed.systems/mcp/sse") -> str:
        """
        Connect to the distributed tool registry (meta-tools for lazy discovery).

        This provides access to meta-tools for searching and executing tools:
        - search_tools: Find tools by description
        - execute_tool: Execute a specific tool
        - compose_workflow: Chain tools together

        Args:
            registry_url: The tool registry SSE URL

        Returns:
            Server name for the registry connection.
        """
        return await self.connect_to_http_server(registry_url, server_name="tool_registry")

    async def connect_to_distributed_mcps(self) -> List[str]:
        """
        Connect directly to all distributed MCP servers for full tool access.

        This fetches tools from each backend and registers them locally.
        Tools are namespaced by backend (e.g., search_mcp__search).

        - Search MCP: search, read, verify, rerank, embed
        - Research MCP: deep_search, run_task, extract_data, synthesize
        - Publish MCP: webhooks, events, notifications
        - Memory MCP: working_memory, episodic_memory, semantic_memory

        Returns:
            List of connected server names.
        """
        backends = [
            ("https://arthurcolle--distributed-search-mcp-web.modal.run/mcp/sse", "search_mcp"),
            ("https://arthurcolle--distributed-research-mcp-web.modal.run/mcp/sse", "research_mcp"),
            ("https://arthurcolle--distributed-publish-mcp-web.modal.run/mcp/sse", "publish_mcp"),
            ("https://arthurcolle--distributed-memory-mcp-web.modal.run/mcp/sse", "memory_mcp"),
        ]

        connected = []
        for url, name in backends:
            try:
                await self._register_http_mcp_tools(url, name)
                connected.append(name)
                logger.info("Registered tools from %s at %s", name, url)
            except Exception as exc:
                logger.warning("Failed to connect to %s: %s", name, exc)

        return connected

    async def _register_http_mcp_tools(self, mcp_url: str, server_name: str) -> None:
        """
        Register tools from an HTTP JSON-RPC MCP server.

        This fetches tools via tools/list and registers them for local execution.
        Tool calls are proxied to the remote server.
        """
        import httpx as httpx_lib

        async with httpx_lib.AsyncClient(timeout=30.0) as client:
            # Initialize
            init_response = await client.post(
                mcp_url,
                json={
                    "jsonrpc": "2.0",
                    "id": str(uuid.uuid4()),
                    "method": "initialize",
                    "params": {
                        "clientInfo": {"name": "mcp_client_v1", "version": "1.0"},
                        "capabilities": {}
                    }
                }
            )
            init_response.raise_for_status()

            # List tools
            tools_response = await client.post(
                mcp_url,
                json={
                    "jsonrpc": "2.0",
                    "id": str(uuid.uuid4()),
                    "method": "tools/list",
                    "params": {}
                }
            )
            tools_response.raise_for_status()
            tools_data = tools_response.json()

            tools = tools_data.get("result", {}).get("tools", [])

            # Register each tool
            self._remove_mcp_tools_for_server(server_name)
            registered_names: List[str] = []

            for tool in tools:
                remote_name = tool.get("name")
                if not remote_name:
                    continue

                # Convert to OpenAI function format
                formatted = {
                    "type": "function",
                    "function": {
                        "name": f"{server_name}__{remote_name}",
                        "description": tool.get("description", ""),
                        "parameters": tool.get("inputSchema", {"type": "object", "properties": {}})
                    }
                }

                sanitized_name = formatted["function"]["name"]
                # Store mapping: sanitized_name -> (server_name, remote_name, mcp_url)
                self.mcp_tool_registry[sanitized_name] = (server_name, remote_name, mcp_url)
                self.mcp_tool_schemas.append(formatted)
                registered_names.append(sanitized_name)

                # Index for retrieval
                if self.tool_retriever:
                    self.tool_retriever.index_tool(
                        sanitized_name,
                        tool.get("description", ""),
                        server_name=server_name,
                        is_builtin=False
                    )

            if registered_names:
                self.mcp_tools_by_server[server_name] = registered_names
                logger.info("Registered %d HTTP MCP tools from %s", len(registered_names), server_name)

    async def _execute_http_mcp_tool(self, mcp_url: str, tool_name: str, arguments: Dict[str, Any]) -> str:
        """
        Execute a tool on an HTTP MCP server via JSON-RPC.

        Args:
            mcp_url: The MCP endpoint URL (e.g., /mcp/sse)
            tool_name: The tool name to call
            arguments: Tool arguments

        Returns:
            JSON string of the tool result
        """
        import httpx as httpx_lib

        async with httpx_lib.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                mcp_url,
                json={
                    "jsonrpc": "2.0",
                    "id": str(uuid.uuid4()),
                    "method": "tools/call",
                    "params": {
                        "name": tool_name,
                        "arguments": arguments
                    }
                }
            )
            response.raise_for_status()
            data = response.json()

            if "error" in data:
                error_msg = data["error"].get("message", "Unknown error")
                raise RuntimeError(f"MCP tool error: {error_msg}")

            result = data.get("result", {})
            content = result.get("content", [])

            # Extract text content from MCP response format
            if isinstance(content, list):
                texts = []
                for item in content:
                    if isinstance(item, dict) and item.get("type") == "text":
                        texts.append(item.get("text", ""))
                    elif isinstance(item, str):
                        texts.append(item)
                return "\n".join(texts) if texts else _json_dumps(result)

            return _json_dumps(result)

    async def disconnect(self) -> None:
        if not (self.session or self.mcp_sessions):
            return
        await self.exit_stack.aclose()
        self.exit_stack = AsyncExitStack()
        self.session = None
        self.mcp_sessions.clear()
        self.mcp_tool_registry.clear()
        self.mcp_tool_schemas.clear()
        self.mcp_tools_by_server.clear()

    async def _register_mcp_tools_for_session(self, server_name: str, session: ClientSession) -> None:
        try:
            tools_response = await session.list_tools()
        except Exception as exc:
            logger.warning("Failed to list MCP tools for %s: %s", server_name, exc)
            return

        self._remove_mcp_tools_for_server(server_name)
        registered_names: List[str] = []
        for tool in tools_response.tools:
            formatted = self._convert_tool_format(tool)
            remote_name = formatted.get("function", {}).get("name")
            if not remote_name:
                continue
            sanitized_name = self._format_mcp_tool_name(server_name, remote_name)
            formatted["function"]["name"] = sanitized_name
            self.mcp_tool_registry[sanitized_name] = (server_name, remote_name)
            self.mcp_tool_schemas.append(formatted)
            registered_names.append(sanitized_name)

            # Register/index the tool
            description = formatted.get("function", {}).get("description", "")
            if self.tool_context:
                # Register with Tool Context Manager
                self.tool_context.register_tool(
                    name=sanitized_name,
                    schema=formatted,
                    server_name=server_name,
                    is_builtin=False,
                    auto_load=False  # Load on demand based on semantic retrieval
                )
            elif self.tool_retriever:
                # Index with basic retriever
                self.tool_retriever.index_tool(sanitized_name, description, server_name=server_name, is_builtin=False)

        if registered_names:
            self.mcp_tools_by_server[server_name] = registered_names
            logger.info("Registered %d MCP tool(s) from %s", len(registered_names), server_name)

    def _remove_mcp_tools_for_server(self, server_name: str) -> None:
        previous = self.mcp_tools_by_server.pop(server_name, [])
        if not previous:
            return
        surviving: List[Dict[str, Any]] = []
        names_to_remove = set(previous)
        for schema in self.mcp_tool_schemas:
            function_name = schema.get("function", {}).get("name")
            if function_name not in names_to_remove:
                surviving.append(schema)
            else:
                self.mcp_tool_registry.pop(function_name, None)
        self.mcp_tool_schemas = surviving

    def _format_mcp_tool_name(self, server_name: str, tool_name: str) -> str:
        base = f"{tool_name}".lower()
        base = re.sub(r"[^a-z0-9_]", "_", base)
        base = re.sub(r"_+", "_", base).strip("_") or "mcp_tool"
        candidate = base
        counter = 1
        taken = set(self.native_tool_executors.keys()) | set(self.mcp_tool_registry.keys())
        while candidate in taken:
            counter += 1
            candidate = f"{base}_{counter}"
        return candidate

    def _derive_server_name(self, preferred: Optional[str], command: Optional[str], args: Iterable[str]) -> str:
        if preferred:
            base = preferred
        elif command:
            base = Path(command).stem
        elif args:
            base = Path(str(args[0])).stem
        else:
            base = "mcp"
        base = re.sub(r"[^a-zA-Z0-9_]", "_", base).strip("_") or "mcp"
        candidate = base
        counter = 1
        while candidate in self.mcp_sessions:
            counter += 1
            candidate = f"{base}_{counter}"
        return candidate

    # ------------------------------------------------------------------
    # Reasoning state
    # ------------------------------------------------------------------

    def _choose_strategy_for_query(self, query: str) -> ReasoningStrategy:
        lowered = query.lower()
        if any(keyword in lowered for keyword in ("compare", "contrast", "versus")):
            return ReasoningStrategy.COMPARATIVE
        if any(keyword in lowered for keyword in ("why", "cause", "impact", "effect")):
            return ReasoningStrategy.CRITICAL
        if any(keyword in lowered for keyword in ("design", "brainstorm", "innovate", "creative")):
            return ReasoningStrategy.CREATIVE
        if len(query) > 600 or query.count("?") > 1:
            return ReasoningStrategy.SYSTEMATIC
        if len(query) > 200:
            return ReasoningStrategy.EXPLORATORY
        return ReasoningStrategy.LINEAR

    def _ensure_active_thread(self, strategy: Optional[ReasoningStrategy] = None) -> None:
        if self.active_thread_id and self.active_thread_id in self.reasoning_threads:
            return
        selected_strategy = strategy or ReasoningStrategy.LINEAR
        thread_id = str(uuid.uuid4())
        self.reasoning_threads[thread_id] = ReasoningThread(thread_id=thread_id, strategy=selected_strategy)
        self.active_thread_id = thread_id
        logger.debug("Created reasoning thread %s using strategy %s", thread_id[:8], selected_strategy.value)

    def _branch_thread(self, new_strategy: ReasoningStrategy) -> None:
        if not self.active_thread_id:
            self._ensure_active_thread(new_strategy)
            return
        parent = self.reasoning_threads[self.active_thread_id]
        child = parent.branch(new_strategy)
        self.reasoning_threads[child.thread_id] = child
        self.active_thread_id = child.thread_id
        logger.debug("Branched into reasoning thread %s (strategy=%s)", child.thread_id[:8], new_strategy.value)

    def _prepare_system_message_for_strategy(self) -> Optional[str]:
        if not self.active_thread_id:
            return self.system_prompt
        strategy = self.reasoning_threads[self.active_thread_id].strategy
        instructions = {
            ReasoningStrategy.LINEAR: "You have access to powerful tools. ALWAYS use available tools to answer questions that require real-time data, web search, or external information. For questions about weather, current events, web content, or anything requiring lookup - USE THE TOOLS.",
            ReasoningStrategy.EXPLORATORY: "Explore multiple avenues using all available tools. Gather context from external sources and synthesize findings.",
            ReasoningStrategy.COMPARATIVE: "Use tools to gather data for comparison. Compare alternatives explicitly with real data.",
            ReasoningStrategy.CRITICAL: "Validate evidence using external tools. Verify claims with real data from available tools.",
            ReasoningStrategy.CREATIVE: "Leverage available tools creatively. Embrace novel ideas with data-backed suggestions.",
            ReasoningStrategy.SYSTEMATIC: "Use tools systematically. For each step, check if a tool can provide better information.",
        }
        base_prompt = self.system_prompt or ""
        strategy_prompt = instructions[strategy]
        return (base_prompt + "\n\n" + strategy_prompt).strip() if base_prompt else strategy_prompt

    def _temperature_for_strategy(self) -> float:
        if not self.active_thread_id:
            return self.temperature
        strategy = self.reasoning_threads[self.active_thread_id].strategy
        adjustments = {
            ReasoningStrategy.LINEAR: 0.0,
            ReasoningStrategy.EXPLORATORY: 0.1,
            ReasoningStrategy.COMPARATIVE: -0.05,
            ReasoningStrategy.CRITICAL: -0.1,
            ReasoningStrategy.CREATIVE: 0.2,
            ReasoningStrategy.SYSTEMATIC: -0.05,
        }
        value = max(0.0, min(1.5, self.temperature + adjustments.get(strategy, 0.0)))
        return value

    def _estimate_iteration_budget(self, query: str) -> int:
        base = self.default_max_iterations
        length_factor = min(3, max(0, len(query) // 250))
        question_marks = query.count("?")
        reasoning_weight = 2 if any(kw in query.lower() for kw in ("analyze", "evaluate", "plan", "why", "how")) else 0
        estimated = base + length_factor + question_marks + reasoning_weight
        estimated = max(1, min(estimated, 12))
        self.iteration_history.append({"query_length": len(query), "estimated_iterations": estimated})
        return estimated

    # ------------------------------------------------------------------
    # Tool handling
    # ------------------------------------------------------------------

    def _convert_tool_format(self, tool: Any) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": tool.name,
                "description": getattr(tool, "description", ""),
                "parameters": {
                    "type": "object",
                    "properties": tool.inputSchema.get("properties", {}),
                    "required": tool.inputSchema.get("required", []),
                },
            },
        }

    def _builtin_session_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "type": "function",
                "function": {
                    "name": "_start_terminal_session",
                    "description": "Start a new terminal session with streaming output.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "shell": {"type": "string", "description": "Shell path (default: /bin/bash)", "default": "/bin/bash"}
                        },
                        "required": [],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "_start_jupyter_session",
                    "description": "Start a Jupyter console session with optional uv enhancements.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "notebook_path": {"type": "string"},
                            "packages": {"type": "array", "items": {"type": "string"}},
                            "requirements": {"type": "array", "items": {"type": "string"}},
                            "python": {"type": "string"},
                            "extra_args": {"type": "array", "items": {"type": "string"}},
                            "environment": {"type": "object"},
                            "kernel_name": {"type": "string"},
                            "use_uv": {"type": "boolean", "default": True},
                            "working_directory": {"type": "string"},
                        },
                        "required": [],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "_send_to_session",
                    "description": "Send input to an existing session.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "session_id": {"type": "string"},
                            "command": {"type": "string"},
                        },
                        "required": ["session_id", "command"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "_get_session_output",
                    "description": "Retrieve buffered output from a session.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "session_id": {"type": "string"},
                            "timeout": {"type": "number", "default": 1.0},
                        },
                        "required": ["session_id"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "_list_sessions",
                    "description": "List active sessions.",
                    "parameters": {"type": "object", "properties": {}, "required": []},
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "_kill_session",
                    "description": "Terminate an existing session.",
                    "parameters": {
                        "type": "object",
                        "properties": {"session_id": {"type": "string"}},
                        "required": ["session_id"],
                    },
                },
            },
        ]

    def _builtin_python_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "type": "function",
                "function": {
                    "name": "_run_python",
                    "description": "Execute ad-hoc Python code in a disposable interpreter process.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "code": {"type": "string", "description": "Python source code to execute."},
                            "python": {"type": "string", "description": "Optional path to the Python interpreter."},
                            "timeout": {"type": "number", "default": 30.0, "description": "Seconds before timing out."},
                            "working_directory": {"type": "string", "description": "Directory to run the code in."},
                            "environment": {"type": "object", "description": "Additional environment variables."},
                        },
                        "required": ["code"],
                    },
                },
            }
        ]

    def _builtin_introspection_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "type": "function",
                "function": {
                    "name": "self_introspect",
                    "description": "Inspect the client's self-introspection state (reasoning threads, context, recent decisions).",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "thread_id": {
                                "type": "string",
                                "description": "Optional reasoning thread identifier to inspect.",
                            },
                            "detail_level": {
                                "type": "string",
                                "enum": ["compact", "full"],
                                "default": "compact",
                            },
                            "include_messages": {
                                "type": "boolean",
                                "default": False,
                                "description": "Include recent conversation messages in the snapshot.",
                            },
                        },
                        "required": [],
                    },
                },
            }
        ]

    def _builtin_jina_tools(self) -> List[Dict[str, Any]]:
        if not self.jina.enabled:
            return []
        return [
            {
                "type": "function",
                "function": {
                    "name": "jina_embed",
                    "description": "Generate text embeddings using Jina Embeddings API.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "text": {"type": "string", "description": "Input text to embed"},
                            "model": {"type": "string", "default": "jina-embeddings-v4"},
                            "task": {"type": "string"},
                            "dimensions": {"type": "integer"},
                            "late_chunking": {"type": "boolean", "default": False},
                        },
                        "required": ["text"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "jina_rerank",
                    "description": "Rerank documents using Jina Reranker models.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string"},
                            "documents": {"type": "array", "items": {"type": "string"}},
                            "model": {"type": "string", "default": "jina-reranker-v2-base-multilingual"},
                            "top_k": {"type": "integer"},
                            "return_documents": {"type": "boolean", "default": True},
                        },
                        "required": ["query", "documents"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "jina_read_web",
                    "description": "REQUIRED for fetching real-time web content. Use this to read any URL including weather sites (weather.gov), news, documentation, or any web page. Returns parsed markdown content.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "description": "Full URL to fetch (e.g., https://weather.gov for weather, https://news.site for news)"},
                            "format": {"type": "string", "default": "markdown"},
                            "include_images": {"type": "boolean", "default": True},
                            "include_links": {"type": "boolean", "default": True},
                            "no_cache": {"type": "boolean", "default": False},
                            "max_chars": {"type": "integer", "default": 4000},
                            "store_full_content": {"type": "boolean", "default": True},
                        },
                        "required": ["url"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "jina_search_web",
                    "description": "REQUIRED for web search. Use this for: weather queries, current events, news, looking up information, finding websites. Returns search results with content snippets. Example: 'weather in DC', 'latest news', 'how to X'.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string", "description": "Search query (e.g., 'current weather Washington DC', 'latest AI news')"},
                            "search_type": {"type": "string", "default": "search"},
                            "include_images": {"type": "boolean", "default": False},
                            "include_links": {"type": "boolean", "default": True},
                            "no_cache": {"type": "boolean", "default": False},
                            "site": {"type": "string", "description": "Limit search to specific site (e.g., 'weather.gov')"},
                            "country": {"type": "string"},
                            "top_k": {"type": "integer", "default": 5},
                        },
                        "required": ["query"],
                    },
                },
            },
        ]

    def _get_builtin_tools(self) -> List[Dict[str, Any]]:
        if self.mcp_only:
            return []
        tools = self._builtin_session_tools()
        tools.extend(self._builtin_python_tools())
        tools.extend(self._builtin_introspection_tools())
        # Only add builtin Jina tools if no MCP Jina tools are available
        jina_mcp_tools = [t for t in self.mcp_tool_schemas if "jina" in t["function"]["name"].lower()]
        if not jina_mcp_tools:
            tools.extend(self._builtin_jina_tools())
        tools.extend(self.native_tool_schemas)
        return tools

    async def _execute_builtin_tool(self, name: str, arguments: Dict[str, Any]) -> str:
        start = time.perf_counter()
        try:
            if name in self.native_tool_executors:
                return await self.native_tool_executors[name](arguments)
            if name == "_start_terminal_session":
                shell = arguments.get("shell") or "/bin/bash"
                session_id = self.session_manager.start_terminal_session(shell)
                return f"Started terminal session {session_id}"
            if name == "_start_jupyter_session":
                session_id = self.session_manager.start_jupyter_session(
                    notebook_path=arguments.get("notebook_path"),
                    packages=arguments.get("packages"),
                    requirements=arguments.get("requirements"),
                    python=arguments.get("python"),
                    extra_args=arguments.get("extra_args"),
                    environment=arguments.get("environment"),
                    kernel_name=arguments.get("kernel_name"),
                    use_uv=arguments.get("use_uv", True),
                    working_directory=arguments.get("working_directory"),
                )
                return f"Started Jupyter session {session_id}"
            if name == "_send_to_session":
                ok = self.session_manager.send_to_session(arguments["session_id"], arguments["command"])
                return "Command sent." if ok else "Session not found or not running."
            if name == "_get_session_output":
                output = self.session_manager.get_session_output(arguments["session_id"], timeout=arguments.get("timeout", 1.0))
                if not output:
                    return "No output."
                return "\n".join(f"[{stream}] {line}" for stream, line in output)
            if name == "_list_sessions":
                sessions = self.session_manager.list_sessions()
                if not sessions:
                    return "No active sessions."
                lines = []
                for info in sessions:
                    lines.append(
                        f"{info['session_id']} | {info['type']} | alive={info['is_alive']} | last={time.strftime('%H:%M:%S', time.localtime(info['last_activity']))}"
                    )
                return "\n".join(lines)
            if name == "_kill_session":
                return "Session terminated." if self.session_manager.kill_session(arguments["session_id"]) else "Session not found."
            if name == "_run_python":
                code = arguments.get("code")
                if not code:
                    raise ValueError("Argument 'code' is required for _run_python.")
                result = await asyncio.to_thread(
                    self._run_python_snippet,
                    code,
                    python=arguments.get("python"),
                    timeout=arguments.get("timeout", 30.0),
                    working_directory=arguments.get("working_directory"),
                    environment=arguments.get("environment"),
                )
                return json.dumps(result)

            if name == "self_introspect":
                snapshot = self.build_self_introspection(
                    thread_id=arguments.get("thread_id"),
                    detail_level=arguments.get("detail_level", "compact"),
                    include_messages=bool(arguments.get("include_messages", False)),
                )
                return json.dumps(snapshot)

            if name == "jina_embed":
                response = await self.jina.embed(arguments["text"], model=arguments.get("model", "jina-embeddings-v4"), task=arguments.get("task"), dimensions=arguments.get("dimensions"), late_chunking=arguments.get("late_chunking", False))
                embeddings = response.get("data") or response.get("embeddings")
                if embeddings:
                    preview = embeddings[0].get("embedding") if isinstance(embeddings[0], dict) else embeddings[0]
                    if isinstance(preview, list):
                        preview = preview[:8]
                    return json.dumps({"embedding_preview": preview, "dimensions": response.get("dimensions")})
                return json.dumps(response)
            if name == "jina_rerank":
                response = await self.jina.rerank(
                    query=arguments["query"],
                    documents=arguments["documents"],
                    model=arguments.get("model", "jina-reranker-v2-base-multilingual"),
                    top_k=arguments.get("top_k"),
                    return_documents=arguments.get("return_documents", True),
                )
                return json.dumps(response)
            if name == "jina_read_web":
                response = await self.jina.read(
                    url=arguments["url"],
                    format=arguments.get("format", "markdown"),
                    include_images=arguments.get("include_images", True),
                    include_links=arguments.get("include_links", True),
                    no_cache=arguments.get("no_cache", False),
                    max_chars=arguments.get("max_chars", 4000),
                    store_full_content=arguments.get("store_full_content", True),
                )
                return json.dumps(response)
            if name == "jina_search_web":
                response = await self.jina.search(
                    query=arguments["query"],
                    search_type=arguments.get("search_type", "search"),
                    include_images=arguments.get("include_images", False),
                    include_links=arguments.get("include_links", True),
                    no_cache=arguments.get("no_cache", False),
                    site=arguments.get("site"),
                    country=arguments.get("country"),
                    top_k=arguments.get("top_k", 5),
                )
                return json.dumps(response)
        finally:
            latency = time.perf_counter() - start
            logger.debug("Builtin tool %s completed in %.2fs", name, latency)
        raise ValueError(f"Unknown builtin tool '{name}'")

    async def _execute_tool_call(self, tool_call: Any, iteration: int) -> Dict[str, Any]:
        def _get_attr(obj: Any, key: str, default: Any = None) -> Any:
            if obj is None:
                return default
            if isinstance(obj, dict):
                return obj.get(key, default)
            return getattr(obj, key, default)

        function_payload = _get_attr(tool_call, "function")
        tool_call_id = _get_attr(tool_call, "id") or _get_attr(tool_call, "tool_call_id")
        tool_name = _get_attr(function_payload, "name")
        raw_arguments = _get_attr(function_payload, "arguments")

        if not tool_name:
            raise ValueError("Tool call missing function name.")
        if not tool_call_id:
            tool_call_id = f"{tool_name}-{iteration}"

        arguments: Dict[str, Any] = {}
        try:
            if raw_arguments:
                if isinstance(raw_arguments, str):
                    arguments = json.loads(raw_arguments)
                elif isinstance(raw_arguments, dict):
                    arguments = raw_arguments
                else:
                    arguments = {"__raw_arguments": raw_arguments}
        except json.JSONDecodeError:
            arguments = {"__raw_arguments": raw_arguments}

        start = time.perf_counter()
        try:
            if tool_name in {tool["function"]["name"] for tool in self._get_builtin_tools()}:
                result = await self._execute_builtin_tool(tool_name, arguments)
                latency = time.perf_counter() - start
                self._log_function_call(tool_name, arguments, result, True, iteration, latency)

                # Record for RL training
                if self.tool_context:
                    # Estimate token usage for tool response
                    tokens_used = len(str(result)) // 4
                    self.tool_context.record_tool_use(tool_name, success=True, latency=latency, tokens_used=tokens_used)
                if self.learning:
                    self.learning.record_tool_use(tool_name, True)

                return {"tool_call_id": tool_call_id, "name": tool_name, "content": result, "success": True}

            if tool_name in self.mcp_tool_registry:
                registry_entry = self.mcp_tool_registry[tool_name]
                # Handle both 2-tuple (SSE session) and 3-tuple (HTTP direct) formats
                if len(registry_entry) == 3:
                    # HTTP-based MCP tool (registered via _register_http_mcp_tools)
                    server_name, remote_tool_name, mcp_url = registry_entry
                    content = await self._execute_http_mcp_tool(mcp_url, remote_tool_name, arguments)
                else:
                    # SSE session-based tool
                    server_name, remote_tool_name = registry_entry
                    session = self.mcp_sessions.get(server_name)
                    if not session:
                        raise RuntimeError(f"MCP server '{server_name}' is not connected.")
                    response = await session.call_tool(remote_tool_name, arguments)
                    raw_content = response.content if hasattr(response, "content") else response
                    content = _json_dumps(raw_content)
                latency = time.perf_counter() - start
                self._log_function_call(tool_name, arguments, content, True, iteration, latency)

                # Record for RL training
                if self.tool_context:
                    tokens_used = len(str(content)) // 4
                    self.tool_context.record_tool_use(tool_name, success=True, latency=latency, tokens_used=tokens_used)
                if self.learning:
                    self.learning.record_tool_use(tool_name, True)

                return {"tool_call_id": tool_call_id, "name": tool_name, "content": content, "success": True}

            if self.session:
                try:
                    response = await self.session.call_tool(tool_name, arguments)
                    raw_content = response.content if hasattr(response, "content") else response
                    content = _json_dumps(raw_content)
                except Exception as exc:
                    latency = time.perf_counter() - start
                    self._log_function_call(tool_name, arguments, str(exc), False, iteration, latency)
                    raise
                latency = time.perf_counter() - start
                self._log_function_call(tool_name, arguments, content, True, iteration, latency)
                if self.learning:
                    self.learning.record_tool_use(tool_name, True)
                return {"tool_call_id": tool_call_id, "name": tool_name, "content": content, "success": True}

            latency = time.perf_counter() - start
            message = f"No MCP session available for tool '{tool_name}'."
            self._log_function_call(tool_name, arguments, message, False, iteration, latency)
            return {"tool_call_id": tool_call_id, "name": tool_name, "content": message, "success": False}
        except Exception as exc:
            latency = time.perf_counter() - start
            msg = str(exc)
            self._log_function_call(tool_name, arguments, msg, False, iteration, latency)

            # Record failure for RL training
            if self.tool_context:
                self.tool_context.record_tool_use(tool_name, success=False, latency=latency, tokens_used=0)
            if self.learning:
                self.learning.record_tool_use(tool_name, False)
                self.learning.record_error(exc, {"tool": tool_name, "arguments": arguments})
            return {"tool_call_id": tool_call_id, "name": tool_name, "content": msg, "success": False}

    def export_rl_training_data(self) -> Optional[Dict[str, Any]]:
        """Export RL training data from Tool Context Manager."""
        if self.tool_context and self.enable_rl_tracking:
            return self.tool_context.get_rl_training_data()
        return None

    def reset_rl_episode(self) -> None:
        """Reset RL training episode."""
        if self.tool_context:
            self.tool_context.reset_episode()

    # ------------------------------------------------------------------
    # Conversation handling
    # ------------------------------------------------------------------

    def _estimate_token_count(self, messages: List[Dict[str, Any]], tools: Optional[List[Dict[str, Any]]] = None) -> int:
        """Rough token count estimation (4 chars ≈ 1 token)."""
        total_chars = sum(len(str(msg)) for msg in messages)
        if tools:
            total_chars += sum(len(str(tool)) for tool in tools)
        return total_chars // 4

    async def _call_openrouter(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: Optional[float] = None,
        use_transform: bool = False,
        stream: bool = False,
        parallel_tool_calls: bool = True,
        provider_preferences: Optional[Dict[str, Any]] = None
    ) -> Any:
        params = {
            "model": self.model,
            "messages": messages,
            "tools": tools or None,
            "temperature": temperature if temperature is not None else self.temperature,
            "max_tokens": self.max_tokens,
            "tool_choice": "auto" if tools and self.multi_turn_enabled else None,
            "stream": stream,
        }

        # Enable parallel tool calls for faster multi-turn
        if tools and parallel_tool_calls:
            params["parallel_tool_calls"] = True

        # Add stream_options to get usage data with streaming
        if stream:
            params["stream_options"] = {"include_usage": True}

        # Add middle-out transform if enabled and needed
        if use_transform and self.enable_middle_out:
            params.setdefault("extra_body", {})["transforms"] = ["middle-out"]
            logger.info("Using middle-out transform for context compression")

        # Advanced provider routing (OpenRouter feature)
        if provider_preferences:
            params["provider"] = provider_preferences

        # Use realtime dynamics - no timeouts
        return await asyncio.to_thread(self.openai.chat.completions.create, **params)

    async def _call_openrouter_streaming(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: Optional[float] = None,
        use_transform: bool = False,
        ui: Optional[RealtimeUI] = None,
        parallel_tool_calls: bool = True,
        provider_preferences: Optional[Dict[str, Any]] = None
    ) -> Any:
        """Call OpenRouter with streaming and real-time UI updates."""

        def sync_stream_processor():
            """Process stream synchronously in a thread."""
            params = {
                "model": self.model,
                "messages": messages,
                "tools": tools or None,
                "temperature": temperature if temperature is not None else self.temperature,
                "max_tokens": self.max_tokens,
                "tool_choice": "auto" if tools and self.multi_turn_enabled else None,
                "stream": True,
                "stream_options": {"include_usage": True}
            }

            # Enable parallel tool calls
            if tools and parallel_tool_calls:
                params["parallel_tool_calls"] = True

            if use_transform and self.enable_middle_out:
                params.setdefault("extra_body", {})["transforms"] = ["middle-out"]

            # Provider routing preferences
            if provider_preferences:
                params["provider"] = provider_preferences

            stream = self.openai.chat.completions.create(**params)

            # Immediately notify UI that streaming started
            if ui:
                ui.update_iteration(0, status="streaming", detail="Connected, receiving tokens...")

            content_parts: List[str] = []
            tool_calls_data = {}
            finish_reason = None
            usage = None

            # Streaming image capture to avoid spewing base64 in UI/history
            capturing_image = False
            image_buffer: List[str] = []
            image_ext: Optional[str] = None

            def _detect_image_start(s: str) -> Optional[Tuple[int, str]]:
                # Data URL start
                m = re.search(r"data:image/(png|jpeg|jpg|gif);base64,", s, re.IGNORECASE)
                if m:
                    return m.start(), m.group(1).lower()
                # Common raw base64 headers
                for hdr, ext in (("iVBORw0KGgo", "png"), ("/9j/", "jpg"), ("R0lGODdh", "gif"), ("R0lGODlh", "gif")):
                    idx = s.find(hdr)
                    if idx != -1:
                        return idx, ext
                return None

            def _append_clean_piece(piece: str) -> None:
                if piece:
                    content_parts.append(piece)
                    if ui:
                        ui.append_assistant_fragment(piece)

            for chunk in stream:
                if not chunk.choices:
                    # Final chunk with usage
                    if hasattr(chunk, 'usage') and chunk.usage:
                        usage = chunk.usage
                    continue

                delta = chunk.choices[0].delta

                # Stream content with image suppression
                if delta.content:
                    text = delta.content
                    if not capturing_image:
                        hit = _detect_image_start(text)
                        if hit:
                            start, ext = hit
                            # Append any text before image
                            _append_clean_piece(text[:start])
                            capturing_image = True
                            image_ext = ext
                            # Strip data URL header if present and start capturing
                            after = text[start:]
                            after = re.sub(r"^data:image/(png|jpeg|jpg|gif);base64,", "", after, flags=re.IGNORECASE)
                            image_buffer.append(after)
                            if ui:
                                ui.append_assistant_fragment(f"[image:{ext}]")
                            continue
                        else:
                            _append_clean_piece(text)
                    else:
                        # Continue accumulating image base64 only
                        image_buffer.append(text)
                        continue

                # Accumulate tool calls
                if delta.tool_calls:
                    for tc in delta.tool_calls:
                        idx = tc.index
                        if idx not in tool_calls_data:
                            tool_calls_data[idx] = {
                                "id": "",
                                "type": "function",
                                "function": {"name": "", "arguments": ""}
                            }

                        if tc.id:
                            tool_calls_data[idx]["id"] = tc.id
                        if tc.function:
                            if tc.function.name:
                                tool_calls_data[idx]["function"]["name"] = tc.function.name
                                # Notify UI about tool call detection
                                if ui:
                                    ui.update_iteration(0, status="tool call detected", detail=f"Preparing {tc.function.name}")
                            if tc.function.arguments:
                                tool_calls_data[idx]["function"]["arguments"] += tc.function.arguments

                # Track finish reason
                if chunk.choices[0].finish_reason:
                    finish_reason = chunk.choices[0].finish_reason

            # If an image was captured, decode and save it; append placeholder
            if capturing_image and image_buffer:
                try:
                    raw = "".join(image_buffer)
                    cleaned = re.sub(r"[^A-Za-z0-9+/=]", "", raw)
                    data = base64.b64decode(cleaned, validate=False)
                    saved_path = self._save_image_bytes(data, image_ext or "png")
                    note = f"\n[Saved image → {saved_path}]\n"
                    _append_clean_piece(note)
                    # Try to render inline when supported
                    self._try_inline_image_display(saved_path)
                except Exception:
                    if ui:
                        ui.add_tool_event("image decode error — omitted")

            # Build assistant message
            assistant_message = {
                "role": "assistant",
                "content": "".join(content_parts) if content_parts else None,
            }

            if tool_calls_data:
                assistant_message["tool_calls"] = [
                    {
                        "id": tc["id"],
                        "type": "function",
                        "function": {
                            "name": tc["function"]["name"],
                            "arguments": tc["function"]["arguments"]
                        }
                    }
                    for tc in sorted(tool_calls_data.values(), key=lambda x: x.get("id", ""))
                ]

            # Create response object matching OpenAI format
            response = type('Response', (), {
                'choices': [type('Choice', (), {
                    'message': type('Message', (), {
                        'model_dump': lambda self: assistant_message
                    })(),
                    'finish_reason': finish_reason
                })()],
                'usage': usage
            })()

            return response

        return await asyncio.to_thread(sync_stream_processor)

    async def _get_relevant_tools_for_query(self, query: str) -> List[Dict[str, Any]]:
        """Get tools relevant to the current query using semantic retrieval."""
        if not self.enable_tool_retrieval:
            # Return all tools if retrieval is disabled
            tools = list(self.mcp_tool_schemas)
            tools.extend(self._get_builtin_tools())
            return tools

        if self.tool_context:
            # Use Tool Context Manager for dynamic loading/eviction
            relevant_names = await self.tool_context.retrieve_and_load_relevant(
                query,
                top_k=self.tool_retrieval_top_k,
                threshold=self.semantic_retrieval_threshold
            )
            logger.info("Tool Context Manager loaded %d/%d tools for query",
                       len(self.tool_context.active_context), len(self.tool_context.registry))

            # Get schemas for loaded tools only
            return self.tool_context.get_active_schemas()

        elif self.tool_retriever:
            # Use basic retriever (original implementation)
            relevant_names = await self.tool_retriever.retrieve_relevant_tools(
                query,
                top_k=self.tool_retrieval_top_k,
                threshold=self.semantic_retrieval_threshold,
                use_rerank=self.enable_tool_reranking
            )
            logger.info("Retrieved %d/%d relevant tools for query", len(relevant_names), len(self.tool_retriever.tool_index))

            # Build tool schemas for relevant tools
            relevant_tools: List[Dict[str, Any]] = []
            relevant_set = set(relevant_names)

            # Add relevant MCP tools
            for schema in self.mcp_tool_schemas:
                name = schema.get("function", {}).get("name")
                if name in relevant_set:
                    relevant_tools.append(schema)

            # Add relevant builtin tools
            for schema in self._get_builtin_tools():
                name = schema.get("function", {}).get("name")
                if name in relevant_set:
                    relevant_tools.append(schema)

            return relevant_tools

        # Fallback if neither system is available
        tools = list(self.mcp_tool_schemas)
        tools.extend(self._get_builtin_tools())
        return tools

    async def process_query(
        self,
        query: str,
        max_iterations: Optional[int] = None,
        *,
        ui: Optional[RealtimeUI] = None,
    ) -> str:
        query = query.strip()
        if not query:
            return "Empty query."

        final_response = ""
        conversation_success = True
        iterations_run = 0

        if ui and not ui.enabled:
            ui = None

        if self.learning:
            self.learning.start_interaction(query)

        self._ensure_active_thread(self._choose_strategy_for_query(query))

        iteration_budget = max_iterations or self._estimate_iteration_budget(query)
        active_strategy = self.reasoning_threads[self.active_thread_id].strategy.value
        logger.info("Processing query (iterations=%d, strategy=%s)", iteration_budget, active_strategy)

        if ui:
            ui.start(query=query, iteration_budget=iteration_budget, strategy=active_strategy, model=self.model)

        user_message = self._build_user_message_with_pinned_images(query)
        self.messages.append(user_message)
        await self.hooks.dispatch("message_appended", message=user_message, role="user")

        result_fragments: List[str] = []

        # Use intelligent semantic tool retrieval
        available_tools = await self._get_relevant_tools_for_query(query)

        try:
            for iteration in range(1, iteration_budget + 1):
                iterations_run = iteration
                if ui:
                    ui.update_iteration(iteration, status="calling model", detail="Dispatching request to model...")
                await self.hooks.dispatch(
                    "before_iteration",
                    iteration=iteration,
                    messages=self.messages,
                    available_tools=available_tools,
                    thread_id=self.active_thread_id,
                )

                system_content = self._prepare_system_message_for_strategy()
                payload_messages = [{"role": "system", "content": system_content}] + self.messages if system_content else list(self.messages)

                # Check if we need compression
                estimated_tokens = self._estimate_token_count(payload_messages, available_tools)
                use_transform = estimated_tokens > 150000  # Enable transform at 150k tokens

                if use_transform:
                    logger.warning("Context approaching limit (%d tokens estimated), enabling middle-out transform", estimated_tokens)
                if ui:
                    detail = f"Context ~{estimated_tokens:,} tokens"
                    ui.update_iteration(iteration, status="streaming", detail=detail)

                # Use streaming when UI is available for instant feedback
                if ui:
                    response = await self._call_openrouter_streaming(
                        payload_messages,
                        tools=available_tools,
                        temperature=self._temperature_for_strategy(),
                        use_transform=use_transform,
                        ui=ui
                    )
                else:
                    response = await self._call_openrouter(
                        payload_messages,
                        tools=available_tools,
                        temperature=self._temperature_for_strategy(),
                        use_transform=use_transform
                    )

                choice = response.choices[0]
                assistant_message = choice.message.model_dump()
                # Post-process any base64 image content to save and replace
                msg_content = assistant_message.get("content")
                if isinstance(msg_content, str) and msg_content:
                    cleaned, saved_paths = self._extract_and_save_images_from_text(msg_content)
                    if saved_paths:
                        assistant_message["content"] = cleaned
                        if ui:
                            for p in saved_paths:
                                ui.add_tool_event(f"saved image → {p}")
                self.messages.append(assistant_message)
                await self.hooks.dispatch("message_appended", message=assistant_message, role="assistant", iteration=iteration)

                content = assistant_message.get("content")
                if content:
                    result_fragments.append(content)
                    if self.active_thread_id:
                        self.reasoning_threads[self.active_thread_id].context.append({"type": "assistant", "content": content, "iteration": iteration})

                tool_calls = assistant_message.get("tool_calls") or []
                if not tool_calls:
                    logger.info("Model responded without tool calls; terminating loop.")
                    if ui:
                        ui.update_iteration(iteration, status="finalizing", detail="Model returned final answer.")
                    break

                if ui:
                    ui.update_iteration(iteration, status="executing tools", detail=f"{len(tool_calls)} tool call(s) dispatched")

                tool_results: List[Dict[str, Any]] = []
                if self.parallel_tools and len(tool_calls) > 1:
                    tool_results = await asyncio.gather(
                        *[self._execute_tool_call(tool_call, iteration) for tool_call in tool_calls]
                    )
                else:
                    for tool_call in tool_calls:
                        tool_results.append(await self._execute_tool_call(tool_call, iteration))

                for result in tool_results:
                    tool_message = {
                        "role": "tool",
                        "tool_call_id": result["tool_call_id"],
                        "name": result["name"],
                        "content": result["content"],
                    }
                    self.messages.append(tool_message)
                    await self.hooks.dispatch("message_appended", message=tool_message, role="tool", iteration=iteration)
                    status_label = "Result" if result["success"] else "Error"
                    result_fragments.append(f"[{status_label}: {result['name']}]\n{result['content']}")
                    if ui:
                        ui.record_tool_event(result["name"], result["success"], str(result["content"]))

            final_response = "\n\n".join(result_fragments).strip() or "No response generated."
            await self.hooks.dispatch("after_conversation", response=final_response, history=self.messages)
            if ui:
                ui.finish(final_response, success=True, iterations=iterations_run)
            return final_response
        except Exception as exc:
            conversation_success = False
            if ui:
                ui.mark_error(str(exc))
                ui.finish(str(exc), success=False, iterations=iterations_run)
            raise
        finally:
            if self.learning:
                self.learning.end_interaction(final_response, success=conversation_success)
            if ui:
                ui.close()

    async def cleanup(self) -> None:
        self.session_manager.cleanup()
        if self.session or self.mcp_sessions:
            await self.disconnect()
        if self._db_connection:
            self._db_connection.close()
            self._db_connection = None

    async def __aenter__(self) -> "MCPOpenRouterClientV1":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.cleanup()

    def get_function_call_summary(self) -> str:
        if not self.function_call_history:
            return "No function calls recorded."
        lines = []
        for entry in self.function_call_history[-20:]:
            status = "OK" if entry["success"] else "ERR"
            result_text = entry.get("result")
            if not isinstance(result_text, str):
                result_text = _coerce_to_json_text(result_text)
            result_text = _truncate_text_to_tokens(result_text or "", max_tokens=1024)

            header = f"{entry['timestamp']} | iter={entry['iteration']} | {entry['tool_name']} | {status}"
            if result_text:
                lines.append(f"{header}\n{result_text}")
            else:
                lines.append(header)
        return "\n".join(lines)

    def build_self_introspection(
        self,
        *,
        thread_id: Optional[str] = None,
        detail_level: str = "compact",
        include_messages: bool = False,
    ) -> Dict[str, Any]:
        """Return a JSON-serializable snapshot of internal reasoning state."""

        def _clip(text: Any, width: int = 160) -> str:
            if text is None:
                return ""
            text_str = _coerce_to_json_text(text)
            text_str = text_str.replace("\n", " ").strip()
            if not text_str:
                return ""
            if len(text_str) <= width:
                return text_str
            return textwrap.shorten(text_str, width=width, placeholder="…")

        detail = (detail_level or "compact").lower()
        limit = 10 if detail == "full" else 4

        threads_payload: List[Dict[str, Any]] = []
        for tid, thread in self.reasoning_threads.items():
            if thread_id and tid != thread_id:
                continue

            decisions_source = thread.decisions if detail == "full" else thread.decisions[-limit:]
            decisions_payload = []
            for entry in decisions_source:
                timestamp = entry.get("timestamp")
                if isinstance(timestamp, (int, float)):
                    timestamp_iso = datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
                else:
                    timestamp_iso = timestamp

                decisions_payload.append(
                    {
                        "type": entry.get("type"),
                        "rationale": _clip(entry.get("rationale")),
                        "content_preview": _clip(entry.get("content")),
                        "timestamp": timestamp_iso,
                        "confidence": entry.get("confidence"),
                    }
                )

            context_source = thread.context if detail == "full" else thread.context[-limit:]
            context_payload = [
                {
                    "type": ctx.get("type"),
                    "iteration": ctx.get("iteration"),
                    "content": _clip(ctx.get("content")),
                }
                for ctx in context_source
            ]

            thread_payload = {
                "thread_id": tid,
                "strategy": thread.strategy.value,
                "depth": thread.depth,
                "confidence": round(thread.confidence, 4),
                "created": datetime.fromtimestamp(thread.created_at, tz=timezone.utc).isoformat(),
                "parent_id": thread.parent_id,
                "children": list(thread.children),
                "decisions": decisions_payload,
                "recent_context": context_payload,
            }
            threads_payload.append(thread_payload)

        snapshot: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "active_thread": self.active_thread_id,
            "thread_count": len(self.reasoning_threads),
            "message_count": len(self.messages),
            "threads": threads_payload,
        }

        if include_messages:
            history_source = self.messages if detail == "full" else self.messages[-limit:]
            snapshot["recent_messages"] = [
                {"role": msg.get("role"), "content": _clip(msg.get("content"))}
                for msg in history_source
            ]

        return snapshot


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Unified MCP ↔ OpenRouter client.")
    parser.add_argument("--workspace", default=os.getcwd(), help="Workspace directory for filesystem MCP server.")
    parser.add_argument("--model", default="anthropic/claude-haiku-4.5", help="Model identifier for OpenRouter.")
    parser.add_argument("--base-url", default="https://openrouter.ai/api/v1", help="OpenRouter-compatible base URL.")
    parser.add_argument("--system-prompt", help="Inline system prompt.")
    parser.add_argument("--system-prompt-file", help="Path to a file containing the system prompt.")
    parser.add_argument("--capabilities", nargs="*", help="Capabilities to advertise (e.g., delegation routing mutation).")
    parser.add_argument("--allow-tools", nargs="*", help="Allowlist of tool names.")
    parser.add_argument("--block-tools", nargs="*", help="Blocklist of tool names.")
    parser.add_argument("--database-path", help="SQLite database path for logging.")
    parser.add_argument("--max-iterations", type=int, help="Maximum tool-calling iterations.")
    parser.add_argument("--temperature", type=float, help="Base sampling temperature.")
    parser.add_argument("--max-tokens", type=int, help="Maximum tokens per completion.")
    parser.add_argument("--no-parallel-tools", action="store_true", help="Disable parallel execution of tool calls.")
    parser.add_argument("--single-turn", action="store_true", help="Disable automatic multi-turn tool calling.")
    parser.add_argument("--server", choices=["filesystem", "none"], default="filesystem", help="Which built-in server to start.")
    parser.add_argument("--server-command", nargs="+", help="Custom server command (overrides --server).")
    parser.add_argument("--no-jina", action="store_true", help="Disable Jina tool exposure even if API key is set.")
    parser.add_argument("--non-interactive", action="store_true", help="Run a single prompt from stdin and exit.")
    parser.add_argument("--prompt", help="If set, process this prompt once and exit.")

    # Tool Context Manager configuration
    parser.add_argument("--enable-context-manager", action="store_true",
                       help="Enable Tool Context Manager for dynamic loading/eviction and RL training.")
    parser.add_argument("--max-loaded-tools", type=int, default=20,
                       help="Maximum number of tools to keep loaded in context (default: 20).")
    parser.add_argument("--tool-load-strategy", choices=["immediate", "lazy", "semantic", "learned"],
                       default="semantic", help="Tool loading strategy (default: semantic).")
    parser.add_argument("--tool-eviction-policy", choices=["lru", "lfu", "cost_aware", "learned"],
                       default="cost_aware", help="Tool eviction policy (default: cost_aware).")
    parser.add_argument("--enable-rl-tracking", action="store_true", default=True,
                       help="Enable RL training data collection (default: True).")
    parser.add_argument("--export-rl-data", help="Export RL training data to specified JSON file.")
    parser.add_argument("--mcp-config", action="append", help="Additional MCP config file(s) to load.")
    parser.add_argument("--mcp-include", nargs="*", help="Specific MCP server names to connect from configs.")
    parser.add_argument("--mcp-exclude", nargs="*", help="Server names to skip when loading configs.")
    parser.add_argument("--mcp-list", action="store_true", help="List available MCP servers from configs and exit.")
    parser.add_argument("--mcp-list-all", action="store_true", help="List all configured servers even if env vars missing.")
    parser.add_argument("--no-mcp-config", action="store_true", help="Skip automatic MCP config discovery.")
    parser.add_argument("--load-local-mcps", action="store_true", dest="load_local_mcps",
                       help="Also load local MCP server configs (disabled by default; uses tools.distributed.systems only).")

    # Tool Registry (HTTP/SSE MCP server) configuration
    parser.add_argument("--tool-registry", default=None,
                       help="URL of HTTP MCP tool registry (default: https://tools.distributed.systems/mcp/sse)")
    parser.add_argument("--use-distributed-tools", action="store_true",
                       help="Connect to tools.distributed.systems tool registry for Search/Research/Publish/Memory MCPs.")
    parser.add_argument("--connect-all-mcps", action="store_true",
                       help="Connect directly to all distributed MCP servers (Search, Research, Publish, Memory).")
    parser.add_argument("--http-mcp", action="append", metavar="URL",
                       help="Connect to an HTTP/SSE MCP server (can be specified multiple times).")
    return parser.parse_args(argv)


def _load_system_prompt(args: argparse.Namespace) -> Optional[str]:
    if args.system_prompt_file:
        try:
            return Path(args.system_prompt_file).expanduser().read_text()
        except OSError as exc:
            logger.error("Failed to read system prompt file: %s", exc)
    return args.system_prompt


def _build_server_config(args: argparse.Namespace, workspace_path: Path) -> Optional[ServerConfig]:
    if args.server_command:
        command = args.server_command[0]
        return ServerConfig(command=command, args=args.server_command[1:], env=None)

    if args.server == "none":
        return None

    # Default filesystem MCP server with fallbacks when Node tooling is unavailable.
    candidate_launchers: List[Tuple[str, List[str]]] = [
        ("npx", ["-y", "@modelcontextprotocol/server-filesystem", str(workspace_path)]),
        ("pnpm", ["dlx", "@modelcontextprotocol/server-filesystem", str(workspace_path)]),
        ("yarn", ["dlx", "@modelcontextprotocol/server-filesystem", str(workspace_path)]),
        ("bunx", ["@modelcontextprotocol/server-filesystem", str(workspace_path)]),
    ]

    for command, command_args in candidate_launchers:
        if shutil.which(command):
            return ServerConfig(command=command, args=command_args, env=None)

    warning = (
        "No supported package runner (npx/pnpm/yarn/bunx) found for the default "
        "filesystem MCP server. Install Node.js tooling or provide --server-command/--server none."
    )
    logger.warning(warning)
    print(f"Warning: {warning}")
    return None


def _print_mcp_summary(servers: Dict[str, MCPServerConfig]) -> None:
    print("\n=== MCP Servers ===\n")
    if not servers:
        print("  (none discovered)\n")
        return
    for name, server in servers.items():
        status = "✓" if server.is_available() else "✗"
        auto = " [auto]" if server.auto_enable else ""
        print(f"  {status} {name}{auto}")
        print(f"      Command: {server.command}")
        if server.args:
            print(f"      Args:    {' '.join(server.args)}")
        print(f"      Source:  {server.source}")
        if server.required_env:
            missing = [env for env in server.required_env if not os.getenv(env)]
            if missing:
                print(f"      Missing ENV: {', '.join(missing)}")
        if server.env:
            print(f"      Env keys: {', '.join(server.env.keys())}")
        print()


async def _interactive_loop(client: MCPOpenRouterClientV1) -> None:
    print("\n" + "="*80)
    print("🤖 MCP Chat Client Ready!")
    print("="*80)
    print("\nType 'help' for commands. Press Ctrl+C to exit.\n")
    while True:
        try:
            query = input("\n>>> ").strip()
        except KeyboardInterrupt:
            print("\nInterrupted. Type 'quit' to exit.")
            continue
        except EOFError:
            print("\nEOF received. Exiting.")
            break

        if not query:
            continue
        if query.lower() in {"quit", "exit"}:
            break
        if query.lower() == "history":
            print(client.get_function_call_summary())
            continue
        if query.lower() == "toggle-logging":
            client.enable_logging = not client.enable_logging
            print(f"Function call logging: {'ENABLED' if client.enable_logging else 'DISABLED'}")
            continue
        if query.lower() == "toggle-verbose":
            client.verbose_mode = not client.verbose_mode
            print(f"Verbose mode: {'ENABLED' if client.verbose_mode else 'DISABLED'}")
            continue
        if query.lower().startswith("introspect"):
            parts = query.split()
            detail = "compact"
            include_messages = False
            thread = None
            for part in parts[1:]:
                lower = part.lower()
                if lower in {"compact", "full"}:
                    detail = lower
                elif lower in {"messages", "msgs"}:
                    include_messages = True
                else:
                    thread = part
            snapshot = client.build_self_introspection(
                thread_id=thread,
                detail_level=detail,
                include_messages=include_messages
            )
            print(json.dumps(snapshot, indent=2))
            continue
        if query.lower() == "help":
            print(
                "Available commands:\n"
                "  history           Show recent tool call history\n"
                "  toggle-logging    Enable/disable function call logging\n"
                "  toggle-verbose    Enable/disable verbose logging\n"
                "  introspect [full] [messages] [thread_id]\n"
                "  /add_file <path>  Attach a local file (images render inline when possible)\n"
                "  /list_attachments List all attachments; /pin_attachment <id> pins it\n"
                "  /imgcat <id>      Force-inline display of an image (imgcat/wezterm/kitty)\n"
                "  quit / exit       Leave the program\n"
                "Any other input is sent to the model."
            )
            continue
        if integrate_cli_commands:
            modified_query, command_result = await integrate_cli_commands(client, query)
            if command_result is not None:
                print("\n" + json.dumps(command_result, indent=2))
                continue
            if not modified_query:
                continue
            query = modified_query

        ui = RealtimeUI() if RICH_AVAILABLE else None
        if not (ui and ui.enabled):
            print("\nProcessing...")
        try:
            result = await client.process_query(query, ui=ui)
            if not (ui and ui.enabled):
                print("\n" + result)
        except Exception as exc:
            logger.error("Error processing query: %s", exc, exc_info=True)
            if not (ui and ui.enabled):
                print(f"\nError: {exc}")
        finally:
            if ui:
                ui.close()


async def main(argv: Optional[List[str]] = None) -> None:
    _load_env_file()
    args = _parse_args(argv)

    if not os.getenv("OPENROUTER_API_KEY"):
        print("Error: OPENROUTER_API_KEY is not set. Please configure it via environment or .env file.")
        return

    workspace_path = Path(args.workspace).expanduser()
    workspace_path.mkdir(parents=True, exist_ok=True)
    print(f"Workspace directory: {workspace_path}")

    system_prompt = _load_system_prompt(args)
    database_path = Path(args.database_path).expanduser() if args.database_path else None

    client = MCPOpenRouterClientV1(
        model=args.model,
        base_url=args.base_url,
        system_prompt=system_prompt,
        capabilities=args.capabilities,
        allowed_tools=args.allow_tools,
        blocked_tools=args.block_tools,
        database_path=database_path,
        default_max_iterations=args.max_iterations or 6,
        temperature=args.temperature if args.temperature is not None else 0.6,
        max_tokens=args.max_tokens or 4000,
        parallel_tools=not args.no_parallel_tools,
        multi_turn_enabled=not args.single_turn,
        enable_jina=not args.no_jina,
        # Tool Context Manager configuration
        enable_tool_context_manager=args.enable_context_manager,
        max_loaded_tools=args.max_loaded_tools,
        tool_load_strategy=args.tool_load_strategy,
        tool_eviction_policy=args.tool_eviction_policy,
        enable_rl_tracking=args.enable_rl_tracking,
    )

    # Default: connect only to tools.distributed.systems (the unified tool registry)
    # Use --mcp-config or --load-local-mcps to also load local MCP server configs
    registry_url = args.tool_registry or "https://tools.distributed.systems/mcp/sse"

    loaded_mcp_servers: Dict[str, MCPServerConfig] = {}
    load_local = getattr(args, 'load_local_mcps', False) or args.mcp_config
    if load_local and not args.no_mcp_config:
        loaded_mcp_servers = load_mcp_configs(
            config_paths=args.mcp_config,
            include_servers=args.mcp_include,
            exclude_servers=args.mcp_exclude,
            only_available=not args.mcp_list_all,
            auto_enable=not bool(args.mcp_include),
        )
        if args.mcp_list or args.mcp_list_all:
            _print_mcp_summary(loaded_mcp_servers)
            return

    async with client:
        # Primary: connect to tools.distributed.systems MCP via SSE
        try:
            await client.connect_to_http_server(registry_url, server_name="tool_registry")
            logger.info("Connected to tool registry at %s", registry_url)
            print(f"Connected to tool registry: {registry_url}")
        except Exception as exc:
            logger.error("Failed to connect to tool registry at %s: %s", registry_url, exc)
            print(f"Warning: failed to connect to tool registry ({exc}). Continuing without registry tools.")

        # Optional: load local MCP servers if explicitly requested
        if loaded_mcp_servers:
            for name, server in loaded_mcp_servers.items():
                try:
                    await client.connect_to_server(server, server_name=name)
                except Exception as exc:
                    logger.error("Failed to connect to MCP server %s: %s", name, exc)

        # Connect directly to all distributed MCP servers
        if args.connect_all_mcps:
            try:
                connected = await client.connect_to_distributed_mcps()
                logger.info("Connected to %d distributed MCP servers", len(connected))
                print(f"Connected to distributed MCPs: {', '.join(connected)}")
            except Exception as exc:
                logger.error("Failed to connect to distributed MCPs: %s", exc)
                print(f"Warning: failed to connect to some distributed MCPs ({exc}).")

        # Connect to any additional HTTP MCP servers
        if args.http_mcp:
            for url in args.http_mcp:
                try:
                    await client.connect_to_http_server(url)
                    logger.info("Connected to HTTP MCP at %s", url)
                except Exception as exc:
                    logger.error("Failed to connect to HTTP MCP at %s: %s", url, exc)
                    print(f"Warning: failed to connect to HTTP MCP at {url}")

        # Give servers a moment to finish any startup output
        await asyncio.sleep(0.5)

        if args.prompt:
            result = await client.process_query(args.prompt)
            print(result)
            return

        if args.non_interactive:
            prompt = input("Enter prompt: ")
            result = await client.process_query(prompt)
            print(result)
            return

        await _interactive_loop(client)

        # Export RL training data if requested
        if args.export_rl_data:
            rl_data = client.export_rl_training_data()
            if rl_data:
                try:
                    export_path = Path(args.export_rl_data).expanduser()
                    with open(export_path, 'w') as f:
                        json.dump(rl_data, f, indent=2)
                    logger.info("Exported RL training data to %s", export_path)
                    print(f"\nRL training data exported to: {export_path}")
                except Exception as exc:
                    logger.error("Failed to export RL training data: %s", exc)
                    print(f"\nError exporting RL training data: {exc}")
            else:
                logger.info("No RL training data available to export")
                print("\nNo RL training data available (ensure Tool Context Manager is enabled)")


def _configure_signal_handlers(loop: asyncio.AbstractEventLoop) -> None:
    # Store reference to main task
    main_task = None

    def handle_signal(signum: int, frame: Any) -> None:  # pragma: no cover - signal handling is runtime-specific
        # Just set a flag, don't cancel all tasks
        pass  # Let the interactive loop handle KeyboardInterrupt naturally

    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, signal.default_int_handler)  # Use default handler for clean Ctrl+C
    except Exception:
        # Some environments (e.g., Windows) may not support all signals.
        pass


if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    _configure_signal_handlers(loop)
    main_task = loop.create_task(main())
    try:
        loop.run_until_complete(main_task)
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received; beginning graceful shutdown")
        # Ignore subsequent interrupts during cleanup to avoid partial teardown
        try:
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
        except Exception:
            pass

        # Cancel main task so async context managers (__aexit__) can run
        main_task.cancel()
        with suppress(asyncio.CancelledError):
            loop.run_until_complete(main_task)

        # Cancel any remaining tasks and wait for them to finish
        pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
        for t in pending:
            t.cancel()
        if pending:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        # Allow async generators to finalize
        loop.run_until_complete(loop.shutdown_asyncgens())
    finally:
        # Small delay to flush logs/IO, then close loop
        try:
            loop.run_until_complete(asyncio.sleep(0.1))
        except Exception:
            pass
        loop.close()
