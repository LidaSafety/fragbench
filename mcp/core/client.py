from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .execution_policy import ExecutionPolicy
from .tool_registry import MCPToolRegistry


@dataclass
class MCPClientCoreState:
    model: str
    backend: str
    messages: List[Dict[str, Any]]
    mcp_tool_schemas: List[Dict[str, Any]]
    registry: MCPToolRegistry
    execution_policy: ExecutionPolicy


class MCPClientCore:
    """
    Thin state container used to incrementally break down mcp_client_v1.

    This keeps the legacy client stable while new modules move into `mcp/core`.
    """

    def __init__(
        self,
        *,
        model: str,
        backend: str,
        execution_policy: ExecutionPolicy,
        registry: Optional[MCPToolRegistry] = None,
    ) -> None:
        self.state = MCPClientCoreState(
            model=model,
            backend=backend,
            messages=[],
            mcp_tool_schemas=[],
            registry=registry or MCPToolRegistry(),
            execution_policy=execution_policy,
        )
