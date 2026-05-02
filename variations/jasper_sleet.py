"""
JASPER_SLEET Campaign — make_variation implementation.

Generates deterministic variations of the Jasper Sleet (Storm-0287) North
Korean remote IT worker kill chain sourced from Microsoft's 2025-06 and
2026-03 reporting. Operators use generative AI for culturally aligned
personas, AI-tailored resumes, Faceswap and AI image tools for profile
media, voice-changing software for interviews, and AI-assisted daily
communications and code support to sustain long-term employment.
"""

import json
import random
from typing import Any, Dict, List, Tuple

from variations.base import BaseVariation, MitreType


class JasperSleetVariation(BaseVariation):
    """Variation generator for JASPER_SLEET campaign."""

    def __init__(self, seed_file: str = "seeds/jasper_sleet.json"):
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
