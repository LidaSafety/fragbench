from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import httpx

from .base import ChatBackend


@dataclass
class _CompatMessage:
    role: str
    content: str
    tool_calls: Optional[List[Dict[str, Any]]] = None

    def model_dump(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"role": self.role, "content": self.content}
        if self.tool_calls:
            payload["tool_calls"] = self.tool_calls
        return payload


@dataclass
class _CompatChoice:
    message: _CompatMessage
    finish_reason: str = "stop"


@dataclass
class _CompatResponse:
    choices: List[_CompatChoice]


class OllamaBackend(ChatBackend):
    name = "ollama"

    def __init__(self, *, base_url: str = "http://127.0.0.1:11434") -> None:
        self.base_url = base_url.rstrip("/")

    def _convert_tool_calls(self, value: Any) -> List[Dict[str, Any]]:
        if not isinstance(value, list):
            return []
        results: List[Dict[str, Any]] = []
        for idx, item in enumerate(value):
            if not isinstance(item, dict):
                continue
            fn = item.get("function") or {}
            name = fn.get("name")
            if not name:
                continue
            args = fn.get("arguments", {})
            if not isinstance(args, str):
                args = json.dumps(args)
            results.append(
                {
                    "id": item.get("id", f"ollama-tool-{idx}"),
                    "type": "function",
                    "function": {"name": name, "arguments": args},
                }
            )
        return results

    @staticmethod
    def _flatten_messages_to_prompt(messages: List[Dict[str, Any]]) -> str:
        parts: List[str] = []
        for msg in messages:
            role = str(msg.get("role", "user")).upper()
            content = msg.get("content", "")
            if isinstance(content, list):
                text_parts = []
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        text_parts.append(str(part.get("text", "")))
                content = "\n".join(text_parts)
            parts.append(f"[{role}] {content}")
        return "\n\n".join(parts).strip()

    def _normalize_messages_for_ollama(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Convert OpenAI-style message history into Ollama-safe message payload.

        Key normalizations:
        - Convert multimodal content arrays to plain text.
        - Strip OpenAI-only fields (tool_call_id, type, etc.).
        - Convert assistant tool_calls arguments from JSON-string -> object.
        - Fold `role=tool` messages into user text blocks (more broadly supported
          across Ollama builds than OpenAI-native tool role payloads).
        """
        normalized: List[Dict[str, Any]] = []
        for msg in messages:
            role = str(msg.get("role", "user"))
            content = msg.get("content", "")

            if isinstance(content, list):
                text_parts: List[str] = []
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        text_parts.append(str(part.get("text", "")))
                content = "\n".join(text_parts)

            if role == "tool":
                tool_name = str(msg.get("name", "tool"))
                tool_text = str(content or "")
                normalized.append(
                    {
                        "role": "user",
                        "content": f"[Tool result: {tool_name}]\n{tool_text}",
                    }
                )
                continue

            out: Dict[str, Any] = {"role": role, "content": str(content or "")}

            if role == "assistant":
                tool_calls = msg.get("tool_calls") or []
                if isinstance(tool_calls, list) and tool_calls:
                    converted_calls: List[Dict[str, Any]] = []
                    for tc in tool_calls:
                        if not isinstance(tc, dict):
                            continue
                        fn = tc.get("function") or {}
                        name = fn.get("name")
                        if not name:
                            continue
                        args: Any = fn.get("arguments", {})
                        if isinstance(args, str):
                            try:
                                args = json.loads(args)
                            except Exception:
                                args = {"raw_arguments": args}
                        converted_calls.append(
                            {
                                "function": {
                                    "name": str(name),
                                    "arguments": args if isinstance(args, dict) else {"value": args},
                                }
                            }
                        )
                    if converted_calls:
                        out["tool_calls"] = converted_calls

            normalized.append(out)
        return normalized

    async def create_completion(
        self,
        *,
        model: str,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.7,
        max_tokens: int = 1024,
        tool_choice: Optional[str] = None,
        stream: bool = False,
        parallel_tool_calls: bool = True,
        provider_preferences: Optional[Dict[str, Any]] = None,
        use_transform: bool = False,
    ) -> Any:
        if stream:
            raise RuntimeError("Ollama streaming path is not enabled in this client.")

        normalized_messages = self._normalize_messages_for_ollama(messages)
        payload: Dict[str, Any] = {
            "model": model,
            "messages": normalized_messages,
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }
        if tools:
            payload["tools"] = tools
        if tool_choice:
            payload["tool_choice"] = tool_choice

        async def _request() -> Dict[str, Any]:
            async with httpx.AsyncClient(timeout=120.0) as client:
                chat_url = f"{self.base_url}/api/chat"
                response = await client.post(chat_url, json=payload)
                if response.status_code == 404:
                    # Backward-compatible fallback for older/non-chat Ollama API setups.
                    generate_payload: Dict[str, Any] = {
                        "model": model,
                        "prompt": self._flatten_messages_to_prompt(messages),
                        "stream": False,
                        "options": {"temperature": temperature, "num_predict": max_tokens},
                    }
                    gen_url = f"{self.base_url}/api/generate"
                    gen_resp = await client.post(gen_url, json=generate_payload)
                    try:
                        gen_resp.raise_for_status()
                    except httpx.HTTPStatusError as exc:
                        body = gen_resp.text[:500]
                        raise RuntimeError(
                            f"Ollama endpoint error at {gen_url}: {exc}. "
                            f"Response body: {body}"
                        ) from exc
                    gen_raw = gen_resp.json()
                    return {
                        "message": {
                            "role": "assistant",
                            "content": str(gen_raw.get("response", "")),
                            "tool_calls": [],
                        }
                    }
                try:
                    response.raise_for_status()
                except httpx.HTTPStatusError as exc:
                    body = response.text[:500]
                    raise RuntimeError(
                        f"Ollama endpoint error at {chat_url}: {exc}. "
                        f"Response body: {body}"
                    ) from exc
                return response.json()

        raw = await _request()
        message = raw.get("message") or {}
        content = message.get("content", "") or ""
        tool_calls = self._convert_tool_calls(message.get("tool_calls"))
        compat = _CompatResponse(
            choices=[
                _CompatChoice(
                    message=_CompatMessage(
                        role="assistant",
                        content=content,
                        tool_calls=tool_calls or None,
                    )
                )
            ]
        )
        return compat
