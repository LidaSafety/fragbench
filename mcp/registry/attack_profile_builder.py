from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from .toolkit_router import AttackProfile


class AttackProfileBuilder:
    """Builds toolkit-routing profile from seed JSON."""

    def from_seed_file(self, seed_path: Path) -> AttackProfile:
        payload = json.loads(seed_path.read_text())
        return self.from_seed_payload(payload)

    def from_seed_payload(self, payload: Dict[str, Any]) -> AttackProfile:
        metadata = payload.get("metadata", {})
        attack_stages = payload.get("attack_stages", [])
        tactics = {stage.get("mitre_tactic", "") for stage in attack_stages if stage.get("mitre_tactic")}
        techniques = {stage.get("mitre_technique", "") for stage in attack_stages if stage.get("mitre_technique")}
        attack_tags = {tag for tag in metadata.get("tags", []) if isinstance(tag, str)}
        return AttackProfile(
            attack_id=metadata.get("id", "default"),
            tactics=tactics,
            techniques=techniques,
            attack_tags=attack_tags,
        )
