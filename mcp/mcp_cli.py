#!/usr/bin/env python3
"""
MCP CLI - connects to RED-Apt filesystem server on port 8001 via SSE.
"""
from __future__ import annotations

import asyncio
import argparse
import json
import os
import signal
import time
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from mcp_client_v1 import (
    MCPOpenRouterClientV1,
    _configure_signal_handlers,
    _interactive_loop,
    _load_env_file,
)

SERVER_URL = "http://127.0.0.1:8001/mcp"
SERVER_NAME = "filesystem"

LOG_DIR = Path("logs")


class ConversationLogger:
    """Writes structured JSONL logs capturing the full conversation flow."""

    def __init__(self, log_dir: Path, model: str, server: str):
        log_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.path = log_dir / f"session_{ts}.jsonl"
        self.model = model
        self.server = server
        self.seq = 0
        self._query_start: float = 0.0
        self._iter_start: float = 0.0
        self._current_query: str = ""
        self._current_iteration: int = 0
        self._tool_calls_this_iter: int = 0
        self._tool_results_this_iter: int = 0

        self._emit("session_start", {
            "model": model,
            "server": server,
            "pid": os.getpid(),
        })

    def _emit(self, event: str, data: Dict[str, Any]) -> None:
        self.seq += 1
        record = {
            "seq": self.seq,
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **data,
        }
        line = json.dumps(record, default=str, ensure_ascii=False)
        with open(self.path, "a") as f:
            f.write(line + "\n")

    # ── hook: message_appended ──────────────────────────────────────

    def on_message(self, *, message: Dict[str, Any], role: str, **kw: Any) -> None:
        iteration = kw.get("iteration")

        if role == "user":
            content = message.get("content", "")
            if isinstance(content, list):
                # multimodal — pull text parts
                content = " ".join(
                    p.get("text", "") for p in content if isinstance(p, dict) and p.get("type") == "text"
                )
            self._current_query = content[:500]
            self._query_start = time.perf_counter()
            self._emit("user_query", {
                "query": self._current_query,
                "message_count": kw.get("message_count", None),
            })

        elif role == "assistant":
            content = message.get("content") or ""
            tool_calls = message.get("tool_calls") or []
            tool_names = [
                (tc.get("function") or {}).get("name", "?")
                if isinstance(tc, dict)
                else getattr(getattr(tc, "function", None), "name", "?")
                for tc in tool_calls
            ]
            self._tool_calls_this_iter = len(tool_calls)
            self._tool_results_this_iter = 0

            self._emit("assistant_response", {
                "iteration": iteration,
                "has_content": bool(content),
                "content_preview": (content[:300] + "…") if len(content) > 300 else content,
                "tool_calls": tool_names or None,
                "tool_call_count": len(tool_calls),
                "is_final": len(tool_calls) == 0,
            })

        elif role == "tool":
            self._tool_results_this_iter += 1
            tool_name = message.get("name", "?")
            raw = message.get("content", "")
            # try to detect success/failure from the result
            success = True
            if "error" in raw.lower()[:200] or "validation error" in raw.lower()[:200]:
                success = False

            result_preview = raw[:400] + "…" if len(raw) > 400 else raw
            # try to parse for structured preview
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, list) and len(parsed) > 0:
                    first = parsed[0]
                    if isinstance(first, dict) and "text" in first:
                        inner = first["text"]
                        try:
                            inner_parsed = json.loads(inner)
                            result_preview = json.dumps(inner_parsed, indent=None, default=str)[:400]
                            if isinstance(inner_parsed, dict):
                                success = inner_parsed.get("success", success)
                        except (json.JSONDecodeError, TypeError):
                            result_preview = inner[:400]
            except (json.JSONDecodeError, TypeError):
                pass

            self._emit("tool_result", {
                "iteration": iteration,
                "tool": tool_name,
                "success": success,
                "result_preview": result_preview,
                "result_bytes": len(raw),
                "tool_result_index": f"{self._tool_results_this_iter}/{self._tool_calls_this_iter}",
            })

    # ── hook: before_iteration ──────────────────────────────────────

    def on_before_iteration(self, *, iteration: int, messages: List, available_tools: List, **kw: Any) -> None:
        self._current_iteration = iteration
        self._iter_start = time.perf_counter()
        tool_names = []
        for t in available_tools:
            if isinstance(t, dict):
                fn = t.get("function", {})
                tool_names.append(fn.get("name", "?"))

        self._emit("iteration_start", {
            "iteration": iteration,
            "message_count": len(messages),
            "available_tools": tool_names,
            "tool_count": len(available_tools),
            "thread_id": kw.get("thread_id"),
        })

    # ── hook: after_conversation ────────────────────────────────────

    def on_after_conversation(self, *, response: str, history: List, **_kw: Any) -> None:
        elapsed = time.perf_counter() - self._query_start if self._query_start else 0
        # count tool calls across the conversation
        tool_messages = [m for m in history if isinstance(m, dict) and m.get("role") == "tool"]
        assistant_messages = [m for m in history if isinstance(m, dict) and m.get("role") == "assistant"]
        total_tool_calls = 0
        for m in assistant_messages:
            total_tool_calls += len(m.get("tool_calls") or [])

        self._emit("query_complete", {
            "query": self._current_query,
            "elapsed_s": round(elapsed, 3),
            "total_iterations": self._current_iteration,
            "total_tool_calls": total_tool_calls,
            "total_tool_results": len(tool_messages),
            "response_preview": (response[:500] + "…") if len(response) > 500 else response,
            "response_bytes": len(response),
            "final_message_count": len(history),
        })

    # ── lifecycle ───────────────────────────────────────────────────

    def register(self, client: MCPOpenRouterClientV1) -> None:
        client.hooks.register("message_appended", self.on_message)
        client.hooks.register("before_iteration", self.on_before_iteration)
        client.hooks.register("after_conversation", self.on_after_conversation)

    def close(self) -> None:
        self._emit("session_end", {
            "total_events": self.seq,
        })


def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="MCP CLI - filesystem server on 8001")
    p.add_argument("--model", default="anthropic/claude-haiku-4.5")
    p.add_argument("--base-url", default="https://openrouter.ai/api/v1")
    p.add_argument("--server-url", default=SERVER_URL)
    p.add_argument("--server-name", default=SERVER_NAME)
    p.add_argument("--transport", choices=["sse", "streamable-http"], default="sse")
    p.add_argument("--max-iterations", type=int, default=6)
    p.add_argument("--temperature", type=float, default=0.6)
    p.add_argument("--max-tokens", type=int, default=4000)
    p.add_argument("--prompt", help="One-shot prompt, then exit.")
    p.add_argument("--non-interactive", action="store_true")
    p.add_argument("--log-dir", default="logs", help="Directory for session JSONL logs.")
    p.add_argument("--no-log", action="store_true", help="Disable conversation logging.")
    return p.parse_args(argv)


async def main(argv: Optional[List[str]] = None) -> None:
    _load_env_file()
    args = _parse_args(argv)

    if not os.getenv("OPENROUTER_API_KEY"):
        print("Error: OPENROUTER_API_KEY not set.")
        return

    client = MCPOpenRouterClientV1(
        model=args.model,
        base_url=args.base_url,
        default_max_iterations=args.max_iterations,
        temperature=args.temperature,
        max_tokens=args.max_tokens,
        parallel_tools=True,
        multi_turn_enabled=True,
        enable_jina=False,
        enable_tool_retrieval=False,
        enable_tool_context_manager=False,
        enable_rl_tracking=False,
        mcp_only=True,
    )

    conv_logger: Optional[ConversationLogger] = None
    if not args.no_log:
        conv_logger = ConversationLogger(
            log_dir=Path(args.log_dir),
            model=args.model,
            server=args.server_name,
        )
        conv_logger.register(client)
        print(f"Logging to {conv_logger.path}")

    async with client:
        try:
            if args.transport == "sse":
                await client.connect_to_http_server(
                    args.server_url,
                    server_name=args.server_name,
                )
            else:
                await client.connect_to_streamable_http_server(
                    args.server_url,
                    server_name=args.server_name,
                )
            print(f"Connected: {args.server_name} -> {args.server_url} ({args.transport})")
        except Exception as exc:
            print(f"Failed to connect to {args.server_url}: {exc}")
            return

        await asyncio.sleep(0.1)

        try:
            if args.prompt:
                print(await client.process_query(args.prompt))
                return

            if args.non_interactive:
                prompt = input("prompt: ")
                print(await client.process_query(prompt))
                return

            await _interactive_loop(client)
        finally:
            if conv_logger:
                conv_logger.close()
                print(f"\nSession log: {conv_logger.path}")


if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    _configure_signal_handlers(loop)
    task = loop.create_task(main())
    try:
        loop.run_until_complete(task)
    except KeyboardInterrupt:
        with suppress(Exception):
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
        task.cancel()
        with suppress(asyncio.CancelledError):
            loop.run_until_complete(task)
        pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
        for t in pending:
            t.cancel()
        with suppress(asyncio.CancelledError):
            loop.run_until_complete(asyncio.gather(*pending))
    finally:
        loop.close()
