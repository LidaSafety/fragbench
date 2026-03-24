from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

from openai import OpenAI

from .base import ChatBackend


class OpenRouterBackend(ChatBackend):
    name = "openrouter"

    def __init__(self, *, api_key: Optional[str], base_url: str) -> None:
        self.client = OpenAI(
            api_key=api_key,
            base_url=base_url,
            max_retries=3,
        )

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
        params: Dict[str, Any] = {
            "model": model,
            "messages": messages,
            "tools": tools or None,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "tool_choice": tool_choice,
            "stream": stream,
        }
        if tools and parallel_tool_calls:
            params["parallel_tool_calls"] = True
        if stream:
            params["stream_options"] = {"include_usage": True}
        if provider_preferences:
            params["provider"] = provider_preferences
        if use_transform:
            params.setdefault("extra_body", {})["transforms"] = ["middle-out"]
        return await asyncio.to_thread(self.client.chat.completions.create, **params)
