from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class ChatBackend(ABC):
    """Common interface for model backends."""

    name: str

    @abstractmethod
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
        request_metadata: Optional[Dict[str, Any]] = None,
    ) -> Any:
        raise NotImplementedError
