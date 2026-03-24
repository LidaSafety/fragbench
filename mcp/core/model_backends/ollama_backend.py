from __future__ import annotations

import asyncio
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

        payload: Dict[str, Any] = {
            "model": model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }
        if tools:
            payload["tools"] = tools
        if tool_choice:
            payload["tool_choice"] = tool_choice

        async def _request() -> Dict[str, Any]:
            async with httpx.AsyncClient(timeout=120.0) as client:
                response = await client.post(f"{self.base_url}/api/chat", json=payload)
                response.raise_for_status()
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
