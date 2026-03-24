#!/usr/bin/env python3
"""
MCP CLI - connects to RED-Apt filesystem server on port 8001 via SSE.
"""
from __future__ import annotations

import asyncio
import argparse
import json
import os
import re
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

    def __init__(
        self,
        log_dir: Path,
        model: str,
        server: str,
        *,
        run_id: Optional[str] = None,
        campaign: Optional[str] = None,
        attack_id: Optional[str] = None,
        backend: Optional[str] = None,
        toolkit_set: Optional[List[str]] = None,
    ):
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
        self.toolkit_set: List[str] = list(toolkit_set or [])

        self._emit("session_start", {
            "schema_version": "2.0",
            "model": model,
            "server": server,
            "backend": backend or "openrouter",
            "run_id": run_id,
            "campaign": campaign,
            "attack_id": attack_id,
            "toolkit_set": self.toolkit_set,
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

    def _extract_text_thinking_from_payload(self, payload: Any, depth: int = 0) -> Dict[str, List[str]]:
        text_parts: List[str] = []
        thinking_parts: List[str] = []
        if payload is None or depth > 4:
            return {"text": text_parts, "thinking": thinking_parts}

        if hasattr(payload, "model_dump") and callable(getattr(payload, "model_dump")):
            with suppress(Exception):
                payload = payload.model_dump()
        elif hasattr(payload, "to_dict") and callable(getattr(payload, "to_dict")):
            with suppress(Exception):
                payload = payload.to_dict()

        if isinstance(payload, str):
            if payload.strip():
                text_parts.append(payload)
            return {"text": text_parts, "thinking": thinking_parts}

        if isinstance(payload, list):
            for item in payload:
                nested = self._extract_text_thinking_from_payload(item, depth + 1)
                text_parts.extend(nested["text"])
                thinking_parts.extend(nested["thinking"])
            return {"text": text_parts, "thinking": thinking_parts}

        if isinstance(payload, dict):
            ptype = str(payload.get("type") or "").lower()
            if ptype in {"reasoning", "thinking", "thought"}:
                t = payload.get("text")
                if isinstance(t, str) and t.strip():
                    thinking_parts.append(t)

            key_map = {
                "text": "text",
                "content": "text",
                "output_text": "text",
                "response": "text",
                "reasoning": "thinking",
                "thinking": "thinking",
                "reasoning_content": "thinking",
            }
            for key, mode in key_map.items():
                if key not in payload:
                    continue
                value = payload.get(key)
                if isinstance(value, str) and value.strip():
                    if mode == "thinking":
                        thinking_parts.append(value)
                    else:
                        text_parts.append(value)
                else:
                    nested = self._extract_text_thinking_from_payload(value, depth + 1)
                    text_parts.extend(nested["text"])
                    thinking_parts.extend(nested["thinking"])

            for key in ("message", "messages", "choice", "choices", "delta"):
                if key in payload:
                    nested = self._extract_text_thinking_from_payload(payload.get(key), depth + 1)
                    text_parts.extend(nested["text"])
                    thinking_parts.extend(nested["thinking"])
            return {"text": text_parts, "thinking": thinking_parts}

        return {"text": text_parts, "thinking": thinking_parts}

    def _extract_assistant_content(self, content: Any, *fallback_payloads: Any) -> Dict[str, str]:
        """Extract text + thinking from assistant content across provider shapes."""
        text_parts: List[str] = []
        thinking_parts: List[str] = []

        if isinstance(content, str):
            text_parts.append(content)
        elif isinstance(content, list):
            for block in content:
                if not isinstance(block, dict):
                    continue
                btype = str(block.get("type") or "").lower()
                text = block.get("text")
                if btype in {"reasoning", "thinking", "thought"}:
                    if isinstance(text, str) and text.strip():
                        thinking_parts.append(text)
                    continue
                if isinstance(text, str) and text.strip():
                    text_parts.append(text)
        elif content is not None:
            text_parts.append(str(content))

        # Only use fallback payloads to extract thinking; text content is already
        # captured directly from `content` above to avoid duplication (message
        # dicts also contain the same content string as a field).
        for payload in fallback_payloads:
            nested = self._extract_text_thinking_from_payload(payload)
            thinking_parts.extend(nested["thinking"])
            # Only pull text from fallback if primary content extraction found nothing.
            if not text_parts:
                text_parts.extend(nested["text"])

        # Deduplicate adjacent identical parts from double-logging paths.
        seen_text: list[str] = []
        for part in text_parts:
            if part and part not in seen_text:
                seen_text.append(part)
        text_parts = seen_text

        text_full = "\n".join([p for p in text_parts if p]).strip()
        thinking_full = "\n".join([p for p in thinking_parts if p]).strip()

        # Best-effort fallback for models that include hidden reasoning tags in text.
        if not thinking_full and text_full:
            think_matches = re.findall(r"<think>(.*?)</think>", text_full, flags=re.IGNORECASE | re.DOTALL)
            if think_matches:
                thinking_full = "\n\n".join(m.strip() for m in think_matches if m.strip())
                text_full = re.sub(r"<think>.*?</think>", "", text_full, flags=re.IGNORECASE | re.DOTALL).strip()

        if len(text_full) > 6000:
            text_full = text_full[:6000] + "…"
        if len(thinking_full) > 6000:
            thinking_full = thinking_full[:6000] + "…"

        return {
            "content_full": text_full,
            "content_preview": (text_full[:300] + "…") if len(text_full) > 300 else text_full,
            "thinking_full": thinking_full,
            "thinking_preview": (thinking_full[:300] + "…") if len(thinking_full) > 300 else thinking_full,
        }

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
            tool_names: List[str] = []
            tool_call_details: List[Dict[str, Any]] = []
            for tc in tool_calls:
                if isinstance(tc, dict):
                    fn = tc.get("function") or {}
                    name = fn.get("name", "?")
                    raw_args = fn.get("arguments", "")
                else:
                    fn = getattr(tc, "function", None)
                    name = getattr(fn, "name", "?")
                    raw_args = getattr(fn, "arguments", "")
                tool_names.append(name)
                args_preview = raw_args if isinstance(raw_args, str) else json.dumps(raw_args, default=str)
                if len(args_preview) > 1200:
                    args_preview = args_preview[:1200] + "…"
                tool_call_details.append(
                    {
                        "name": name,
                        "arguments_preview": args_preview,
                    }
                )
            self._tool_calls_this_iter = len(tool_calls)
            self._tool_results_this_iter = 0

            content_bits = self._extract_assistant_content(
                content,
                message,
                kw.get("raw_choice"),
                kw.get("raw_response"),
            )
            thinking_raw = message.get("reasoning") or message.get("thinking") or ""
            if thinking_raw and not content_bits["thinking_full"]:
                thinking_full = str(thinking_raw)
                if len(thinking_full) > 6000:
                    thinking_full = thinking_full[:6000] + "…"
                content_bits["thinking_full"] = thinking_full
                content_bits["thinking_preview"] = (
                    thinking_full[:300] + "…" if len(thinking_full) > 300 else thinking_full
                )

            self._emit("assistant_response", {
                "iteration": iteration,
                "has_content": bool(content_bits["content_full"]),
                "content_preview": content_bits["content_preview"],
                "content_full": content_bits["content_full"],
                "thinking_preview": content_bits["thinking_preview"] or None,
                "thinking_full": content_bits["thinking_full"] or None,
                "has_thinking": bool(content_bits["thinking_full"]),
                "tool_calls": tool_names or None,
                "tool_call_details": tool_call_details or None,
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

    def on_llm_response(self, *, iteration: int, assistant_message: Dict[str, Any], raw_choice: Any = None, raw_response: Any = None, **_kw: Any) -> None:
        """Provider-agnostic fallback capture for raw model output."""
        content_bits = self._extract_assistant_content(
            assistant_message.get("content"),
            assistant_message,
            raw_choice,
            raw_response,
        )
        self._emit(
            "llm_response_received",
            {
                "iteration": iteration,
                "content_preview": content_bits["content_preview"] or None,
                "content_full": content_bits["content_full"] or None,
                "thinking_preview": content_bits["thinking_preview"] or None,
                "thinking_full": content_bits["thinking_full"] or None,
            },
        )

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
        client.hooks.register("llm_response_received", self.on_llm_response)
        client.hooks.register("message_appended", self.on_message)
        client.hooks.register("before_iteration", self.on_before_iteration)
        client.hooks.register("after_conversation", self.on_after_conversation)

    def close(self) -> None:
        self._emit("session_end", {
            "total_events": self.seq,
        })

    def update_toolkits(self, toolkits: List[str]) -> None:
        self.toolkit_set = list(toolkits)
        self._emit("toolkits_connected", {"toolkit_set": self.toolkit_set})


def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="MCP CLI - filesystem server on 8001")
    p.add_argument("--model", default="anthropic/claude-haiku-4.5")
    p.add_argument("--base-url", default="https://openrouter.ai/api/v1")
    p.add_argument("--model-backend", choices=["openrouter", "ollama", "vllm"], default="openrouter")
    p.add_argument("--ollama-base-url", default="http://127.0.0.1:11434")
    p.add_argument("--vllm-base-url", default="http://127.0.0.1:8000/v1")
    p.add_argument("--vllm-api-key", default="EMPTY")
    p.add_argument("--server-url", default=SERVER_URL)
    p.add_argument("--server-name", default=SERVER_NAME)
    p.add_argument("--transport", choices=["sse", "streamable-http"], default="sse")
    p.add_argument("--auto-toolkits", action="store_true", help="Connect toolkits selected from registry profile.")
    p.add_argument("--max-iterations", type=int, default=6)
    p.add_argument("--temperature", type=float, default=0.6)
    p.add_argument("--max-tokens", type=int, default=4000)
    p.add_argument("--prompt", help="One-shot prompt, then exit.")
    p.add_argument("--non-interactive", action="store_true")
    p.add_argument("--log-dir", default="logs", help="Directory for session JSONL logs.")
    p.add_argument("--no-log", action="store_true", help="Disable conversation logging.")
    p.add_argument("--run-id", default=None)
    p.add_argument("--campaign", default=None)
    p.add_argument("--attack-id", default=None)
    p.add_argument("--execution-mode", choices=["simulated", "bounded_real"], default="simulated")
    p.add_argument("--execution-root", default=None)
    p.add_argument("--allow-egress-host", action="append", default=[])
    p.add_argument("--attack-seed", default=None, help="Path to a seed JSON for attack-aware toolkit routing.")
    p.add_argument("--registry-path", default=None, help="Path to toolkit registry TOML.")
    return p.parse_args(argv)


async def main(argv: Optional[List[str]] = None) -> None:
    _load_env_file()
    args = _parse_args(argv)

    if args.model_backend == "openrouter" and not os.getenv("OPENROUTER_API_KEY"):
        print("Error: OPENROUTER_API_KEY not set.")
        return

    client = MCPOpenRouterClientV1(
        model=args.model,
        base_url=args.base_url,
        model_backend=args.model_backend,
        ollama_base_url=args.ollama_base_url,
        vllm_base_url=args.vllm_base_url,
        vllm_api_key=args.vllm_api_key,
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
        execution_mode=args.execution_mode,
        execution_root=args.execution_root,
        allowed_egress_hosts=args.allow_egress_host,
        attack_seed_path=args.attack_seed,
        registry_path=args.registry_path,
    )

    connected_toolkits: List[str] = []
    conv_logger: Optional[ConversationLogger] = None
    if not args.no_log:
        conv_logger = ConversationLogger(
            log_dir=Path(args.log_dir),
            model=args.model,
            server=args.server_name,
            run_id=args.run_id,
            campaign=args.campaign,
            attack_id=args.attack_id,
            backend=args.model_backend,
            toolkit_set=connected_toolkits,
        )
        conv_logger.register(client)
        print(f"Logging to {conv_logger.path}")

    async with client:
        try:
            if args.auto_toolkits:
                connected_toolkits.extend(
                    await client.connect_registered_toolkits(attack_seed_path=args.attack_seed)
                )
                print(f"Connected toolkit set: {connected_toolkits if connected_toolkits else '[none]'}")
                if conv_logger:
                    conv_logger.update_toolkits(connected_toolkits)
            else:
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
