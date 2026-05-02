"""
OPERATION_FALSE_WITNESS Campaign — make_variation implementation.

Generates deterministic variations of a recovery-scam fake-law-firm kill
chain sourced from OpenAI's February 2026 disruption report. Operators
used ChatGPT to spin up a network of fictitious law firms, fabricated
attorney profiles, credential-style documents, and authority-styled
client communications to extract recovery-services fees from people
already defrauded by earlier scams.
"""

import json
import random
from typing import Any, Dict, List, Tuple

from variations.base import BaseVariation, MitreType


class OperationFalseWitnessVariation(BaseVariation):
    """Variation generator for OPERATION_FALSE_WITNESS campaign."""

    def __init__(self, seed_file: str = "seeds/operation_false_witness.json"):
        with open(seed_file) as f:
            self.data = json.load(f)
        self._validate_seed_tactics(self.data)

    def make_variation(self, seed: int) -> List[Tuple[str, MitreType]]:
        rng = random.Random(seed)
        dimension_choices = self._select_dimensions(rng)
        resolved_vars: Dict[int, Dict[str, Any]] = {}

        result = []
        for stage in self.data["attack_stages"]:
            stage_vars = self._resolve_variables(
                stage, rng, resolved_vars, dimension_choices
            )
            prompt = stage["baseline_prompt"].format(**stage_vars)
            resolved_vars[stage["index"]] = stage_vars
            result.append((prompt, self._coerce_tactic(stage["mitre_tactic"])))

        return result

    def make_variation_detailed(self, seed: int) -> List[Dict[str, Any]]:
        rng = random.Random(seed)
        dimension_choices = self._select_dimensions(rng)
        resolved_vars: Dict[int, Dict[str, Any]] = {}

        result = []
        for stage in self.data["attack_stages"]:
            stage_vars = self._resolve_variables(
                stage, rng, resolved_vars, dimension_choices
            )
            prompt = stage["baseline_prompt"].format(**stage_vars)
            resolved_vars[stage["index"]] = stage_vars
            result.append({
                "index": stage["index"],
                "prompt": prompt,
                "mitre_tactic": stage["mitre_tactic"],
                "mitre_technique": stage["mitre_technique"],
                "mitre_technique_name": stage["mitre_technique_name"],
                "description": stage["description"],
                "resolved_variables": dict(stage_vars),
                "dimension_choices": dict(dimension_choices),
            })

        return result
