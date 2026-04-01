from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set
import tomllib


@dataclass(frozen=True)
class ToolkitDefinition:
    toolkit_id: str
    description: str
    transport: str
    endpoint: Optional[str] = None
    command: Optional[str] = None
    args: List[str] = field(default_factory=list)
    tags: Set[str] = field(default_factory=set)
    attack_tags: Set[str] = field(default_factory=set)
    execution_modes: Set[str] = field(default_factory=lambda: {"simulated"})
    tool_prefix: Optional[str] = None


class ToolkitRegistry:
    def __init__(self, toolkits: Iterable[ToolkitDefinition]) -> None:
        self._toolkits: Dict[str, ToolkitDefinition] = {t.toolkit_id: t for t in toolkits}

    @classmethod
    def from_toml(cls, path: Path) -> "ToolkitRegistry":
        raw = tomllib.loads(path.read_text())
        toolkit_items = raw.get("toolkit", [])
        toolkits: List[ToolkitDefinition] = []
        for item in toolkit_items:
            toolkits.append(
                ToolkitDefinition(
                    toolkit_id=item["id"],
                    description=item.get("description", ""),
                    transport=item.get("transport", "sse"),
                    endpoint=item.get("endpoint"),
                    command=item.get("command"),
                    args=list(item.get("args", [])),
                    tags=set(item.get("tags", [])),
                    attack_tags=set(item.get("attack_tags", [])),
                    execution_modes=set(item.get("execution_modes", ["simulated"])),
                    tool_prefix=item.get("tool_prefix"),
                )
            )
        return cls(toolkits)

    def get(self, toolkit_id: str) -> Optional[ToolkitDefinition]:
        return self._toolkits.get(toolkit_id)

    def all(self) -> List[ToolkitDefinition]:
        return list(self._toolkits.values())
