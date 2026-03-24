from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional


class MCPToolTransport(str, Enum):
    SESSION = "session"
    HTTP_RPC = "http_rpc"


@dataclass(frozen=True)
class MCPToolRecord:
    local_name: str
    server_name: str
    remote_name: str
    transport: MCPToolTransport = MCPToolTransport.SESSION
    endpoint: Optional[str] = None


class MCPToolRegistry:
    """Typed MCP tool mapping, replacing tuple-length branching."""

    def __init__(self) -> None:
        self._records: Dict[str, MCPToolRecord] = {}

    def clear(self) -> None:
        self._records.clear()

    def set(self, record: MCPToolRecord) -> None:
        self._records[record.local_name] = record

    def get(self, local_name: str) -> Optional[MCPToolRecord]:
        return self._records.get(local_name)

    def pop(self, local_name: str) -> Optional[MCPToolRecord]:
        return self._records.pop(local_name, None)

    def contains(self, local_name: str) -> bool:
        return local_name in self._records

    def names(self) -> List[str]:
        return list(self._records.keys())

    def remove_server(self, server_name: str) -> None:
        to_remove = [name for name, rec in self._records.items() if rec.server_name == server_name]
        for name in to_remove:
            self._records.pop(name, None)
