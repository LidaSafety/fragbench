from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any, Dict

from .toolkit_router import AttackProfile


class AttackProfileBuilder:
    """Builds toolkit-routing profile from attack TOML."""

    def from_seed_file(self, seed_path: Path) -> AttackProfile:
        payload = tomllib.loads(seed_path.read_text())
        return self.from_seed_payload(payload)

    def from_seed_payload(self, payload: Dict[str, Any]) -> AttackProfile:
        metadata = payload.get("metadata", {})
        stages = payload.get("stages", [])
        tactics = {
            stage.get("mitre_tactic", "")
            for stage in stages
            if isinstance(stage, dict) and stage.get("mitre_tactic")
        }
        techniques = {
            stage.get("mitre_technique", "")
            for stage in stages
            if isinstance(stage, dict) and stage.get("mitre_technique")
        }
        technique = metadata.get("technique")
        if isinstance(technique, str) and technique.strip():
            techniques.add(technique.strip())
        attack_tags = {tag for tag in metadata.get("tags", []) if isinstance(tag, str)}
        return AttackProfile(
            attack_id=metadata.get("id", "default"),
            tactics=tactics,
            techniques=techniques,
            attack_tags=attack_tags,
        )
