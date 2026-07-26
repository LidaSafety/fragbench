"""
BENIGN_* — generic variation driver for the executed-benign control set.

The executed-benign corpus exists to answer the reviewer question of whether the
detector separates *cross-session composition* or merely separates two generation
processes. Its chains therefore run through exactly the same
seed -> variation -> fragment -> MCP harness path as every other campaign; only
the objectives are ordinary IT/office work.

This class is deliberately schema-generic: every benign campaign shares it and
differs only in its seed JSON. Behaviour is identical to the other variation
drivers -- resolve each stage's variables with a seeded RNG, render the stage
prompt, and expose per-stage detail so ``run.py`` can render the authored
``fragments[]`` (with their ``produces`` / ``consumes`` wiring) for each stage.

Usage:
    from variations.benign import BenignVariation

    gen = BenignVariation("seeds/benign_sysadmin_capacity.json")
    for prompt, tactic in gen.make_variation(seed=42):
        print(f"[{tactic}] {prompt}")
"""

import json
import random
from typing import Any, Dict, List, Tuple

try:
    from variations.base import BaseVariation, MitreType
except ModuleNotFoundError:
    from base import BaseVariation, MitreType  # type: ignore[no-redef]


class BenignVariation(BaseVariation):
    """Seed-driven variation generator shared by all benign campaigns."""

    def __init__(self, seed_file: str):
        with open(seed_file) as f:
            self.data = json.load(f)
        self._validate_seed_tactics(self.data)

    def _resolve_stages(self, seed: int) -> List[Tuple[dict, Dict[str, Any]]]:
        """Resolve every stage's variables once, honouring cross-stage inherit."""
        rng = random.Random(seed)
        dimension_choices = self._select_dimensions(rng)
        resolved_vars: Dict[int, Dict[str, Any]] = {}
        out: List[Tuple[dict, Dict[str, Any]]] = []
        for stage in self.data["attack_stages"]:
            stage_vars = self._resolve_variables(
                stage, rng, resolved_vars, dimension_choices
            )
            resolved_vars[stage["index"]] = stage_vars
            out.append((stage, stage_vars))
        return out

    def make_variation(self, seed: int) -> List[Tuple[str, MitreType]]:
        return [
            (
                stage["baseline_prompt"].format(**stage_vars),
                self._coerce_tactic(stage["mitre_tactic"]),
            )
            for stage, stage_vars in self._resolve_stages(seed)
        ]

    def make_variation_detailed(self, seed: int) -> List[Dict[str, Any]]:
        return [
            {
                "index": stage["index"],
                "prompt": stage["baseline_prompt"].format(**stage_vars),
                "mitre_tactic": self._coerce_tactic(stage["mitre_tactic"]),
                "mitre_technique": stage["mitre_technique"],
                "mitre_technique_name": stage["mitre_technique_name"],
                "description": stage["description"],
                "resolved_variables": dict(stage_vars),
            }
            for stage, stage_vars in self._resolve_stages(seed)
        ]
