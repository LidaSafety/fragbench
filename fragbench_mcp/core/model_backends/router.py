from __future__ import annotations

import os
from typing import Dict, Optional

from .base import ChatBackend
from .ollama_backend import OllamaBackend
from .openrouter_backend import OpenRouterBackend
from .vllm_backend import VLLMBackend


class ModelBackendRouter:
    """Routes chat-completion requests to configured backend."""

    def __init__(
        self,
        *,
        backend: str = "openrouter",
        openrouter_base_url: str = "https://openrouter.ai/api/v1",
        ollama_base_url: str = "http://127.0.0.1:11434",
        vllm_base_url: str = "http://127.0.0.1:8000/v1",
        vllm_api_key: str = "EMPTY",
    ) -> None:
        self._openrouter_base_url = openrouter_base_url
        self._ollama_base_url = ollama_base_url
        self._vllm_base_url = vllm_base_url
        self._vllm_api_key = vllm_api_key
        self.backends: Dict[str, ChatBackend] = {}
        if backend not in {"openrouter", "ollama", "vllm"}:
            raise ValueError(f"Unsupported model backend '{backend}'.")
        self._active_name = backend
        self._ensure_backend(backend)

    def _ensure_backend(self, name: str) -> ChatBackend:
        if name in self.backends:
            return self.backends[name]
        if name == "openrouter":
            api_key = os.getenv("OPENROUTER_API_KEY")
            if not api_key:
                raise ValueError(
                    "OPENROUTER_API_KEY is required for the openrouter backend. "
                    "Set it in the environment or use --model-backend ollama (or vllm)."
                )
            self.backends[name] = OpenRouterBackend(
                api_key=api_key,
                base_url=self._openrouter_base_url,
            )
        elif name == "ollama":
            self.backends[name] = OllamaBackend(base_url=self._ollama_base_url)
        elif name == "vllm":
            self.backends[name] = VLLMBackend(
                base_url=self._vllm_base_url,
                api_key=self._vllm_api_key,
            )
        else:
            raise ValueError(f"Unsupported model backend '{name}'.")
        return self.backends[name]

    @property
    def active_name(self) -> str:
        return self._active_name

    @property
    def active_backend(self) -> ChatBackend:
        return self._ensure_backend(self._active_name)

    def set_active(self, backend: str) -> None:
        if backend not in {"openrouter", "ollama", "vllm"}:
            raise ValueError(f"Unsupported model backend '{backend}'.")
        self._ensure_backend(backend)
        self._active_name = backend

    def get(self, backend: Optional[str] = None) -> ChatBackend:
        name = backend if backend is not None else self._active_name
        return self._ensure_backend(name)
