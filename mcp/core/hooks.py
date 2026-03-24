from __future__ import annotations

import inspect
from typing import Any, Callable, Dict, List, Optional, Tuple


class HookManager:
    """
    Lightweight event hook dispatcher.

    Supports sync and async callbacks and never raises from hook failures.
    """

    def __init__(self) -> None:
        self._hooks: Dict[str, List[Tuple[int, Callable[..., Any]]]] = {}

    def register(self, event: str, callback: Callable[..., Any], priority: int = 0) -> None:
        if not event or not callable(callback):
            raise ValueError("Hook registration requires a valid event name and callable.")
        self._hooks.setdefault(event, []).append((priority, callback))
        self._hooks[event].sort(key=lambda entry: entry[0], reverse=True)

    def clear(self, event: Optional[str] = None) -> None:
        if event is None:
            self._hooks.clear()
            return
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
            except Exception:
                # Hook failures should be best-effort and non-fatal.
                continue
        if not results:
            return None
        if len(results) == 1:
            return results[0]
        return results
