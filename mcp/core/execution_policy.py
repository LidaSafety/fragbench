from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, Iterable, Optional, Set
from urllib.parse import urlparse


class ExecutionMode(str, Enum):
    SIMULATED = "simulated"
    BOUNDED_REAL = "bounded_real"


@dataclass
class ToolExecutionContext:
    tool_name: str
    arguments: Dict[str, object]
    working_directory: Optional[str] = None
    target_url: Optional[str] = None


@dataclass
class ExecutionPolicy:
    mode: ExecutionMode = ExecutionMode.SIMULATED
    root_dir: Optional[Path] = None
    allowed_tools: Set[str] = field(default_factory=set)
    denied_tools: Set[str] = field(default_factory=set)
    allowed_hostnames: Set[str] = field(default_factory=set)

    @classmethod
    def from_config(
        cls,
        *,
        mode: str = "simulated",
        root_dir: Optional[str] = None,
        allowed_tools: Optional[Iterable[str]] = None,
        denied_tools: Optional[Iterable[str]] = None,
        allowed_hostnames: Optional[Iterable[str]] = None,
    ) -> "ExecutionPolicy":
        normalized_mode = ExecutionMode(mode)
        return cls(
            mode=normalized_mode,
            root_dir=Path(root_dir).resolve() if root_dir else None,
            allowed_tools={t for t in (allowed_tools or []) if t},
            denied_tools={t for t in (denied_tools or []) if t},
            allowed_hostnames={h for h in (allowed_hostnames or []) if h},
        )

    def validate(self, ctx: ToolExecutionContext) -> None:
        if ctx.tool_name in self.denied_tools:
            raise PermissionError(f"Tool '{ctx.tool_name}' is denied by execution policy.")
        if self.allowed_tools and ctx.tool_name not in self.allowed_tools:
            raise PermissionError(f"Tool '{ctx.tool_name}' is not allowlisted.")
        if self.mode == ExecutionMode.BOUNDED_REAL:
            self._validate_bounded_real(ctx)

    def _validate_bounded_real(self, ctx: ToolExecutionContext) -> None:
        if self.root_dir and ctx.working_directory:
            wd = Path(ctx.working_directory).resolve()
            if self.root_dir not in wd.parents and wd != self.root_dir:
                raise PermissionError(
                    f"Working directory '{wd}' is outside execution root '{self.root_dir}'."
                )
        if self.allowed_hostnames and ctx.target_url:
            hostname = (urlparse(ctx.target_url).hostname or "").lower()
            if hostname and hostname not in self.allowed_hostnames:
                raise PermissionError(f"Host '{hostname}' not in egress allowlist.")

