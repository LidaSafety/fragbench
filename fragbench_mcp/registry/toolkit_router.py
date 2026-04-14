from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Set

from .toolkit_registry import ToolkitDefinition, ToolkitRegistry


TACTIC_TO_TAGS = {
    "reconnaissance": {"recon", "network"},
    "initial_access": {"execution", "shell"},
    "credential_access": {"credential", "collection"},
    "discovery": {"filesystem", "recon"},
    "collection": {"filesystem", "archive"},
    "exfiltration": {"exfil", "http"},
    "impact": {"analysis", "ransom"},
}


@dataclass
class AttackProfile:
    attack_id: str = "default"
    tactics: Set[str] = field(default_factory=set)
    techniques: Set[str] = field(default_factory=set)
    attack_tags: Set[str] = field(default_factory=set)

    @property
    def capability_tags(self) -> Set[str]:
        tags: Set[str] = set(self.attack_tags)
        for tactic in self.tactics:
            tags |= TACTIC_TO_TAGS.get(tactic, set())
        return tags


class ToolkitRouter:
    def __init__(self, registry: ToolkitRegistry) -> None:
        self.registry = registry

    def select(self, profile: AttackProfile, *, mode: str = "simulated") -> List[ToolkitDefinition]:
        selected: List[ToolkitDefinition] = []
        needed = profile.capability_tags
        for toolkit in self.registry.all():
            if mode not in toolkit.execution_modes:
                continue
            if toolkit.attack_tags and not (toolkit.attack_tags & profile.attack_tags):
                continue
            if toolkit.tags and needed and not (toolkit.tags & needed):
                continue
            selected.append(toolkit)
        return selected
