"""
HELLO_WORLD — minimal demo variation.

Multi-stage demo: discovery → collection → summarisation.
Used to demonstrate the seed → variation → MCP pipeline end-to-end.

Usage:
    from variations.hello_world import HelloWorldVariation

    gen = HelloWorldVariation("seeds/hello_world.json")
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


class HelloWorldVariation(BaseVariation):
    """Multi-stage demo variation with cross-stage variable inheritance."""

    def __init__(self, seed_file: str = "seeds/hello_world.json"):
        with open(seed_file) as f:
            self.data = json.load(f)
        self._validate_seed_tactics(self.data)

    def make_variation(self, seed: int) -> List[Tuple[str, MitreType]]:
        rng = random.Random(seed)
        stages = self.data["attack_stages"]
        resolved_vars: Dict[int, Dict[str, Any]] = {}
        result = []
        for stage in stages:
            stage_vars = self._resolve_variables(stage, rng, resolved_vars)
            prompt = stage["baseline_prompt"].format(**stage_vars)
            resolved_vars[stage["index"]] = stage_vars
            result.append((prompt, self._coerce_tactic(stage["mitre_tactic"])))
        return result

    def make_variation_detailed(self, seed: int) -> List[Dict[str, Any]]:
        rng = random.Random(seed)
        stages = self.data["attack_stages"]
        resolved_vars: Dict[int, Dict[str, Any]] = {}
        result = []
        for stage in stages:
            stage_vars = self._resolve_variables(stage, rng, resolved_vars)
            prompt = stage["baseline_prompt"].format(**stage_vars)
            resolved_vars[stage["index"]] = stage_vars
            result.append({
                "index": stage["index"],
                "prompt": prompt,
                "mitre_tactic": self._coerce_tactic(stage["mitre_tactic"]),
                "mitre_technique": stage["mitre_technique"],
                "mitre_technique_name": stage["mitre_technique_name"],
                "description": stage["description"],
                "resolved_variables": dict(stage_vars),
            })
        return result

    def _resolve_variables(
        self,
        stage: dict,
        rng: random.Random,
        resolved_vars: Dict[int, Dict[str, Any]],
    ) -> Dict[str, Any]:
        result = {}
        for var_name, var_def in stage.get("variables", {}).items():
            var_type = var_def["type"]

            if var_type == "inherit":
                from_stage = var_def["from_stage"]
                from_var = var_def["variable"]
                result[var_name] = resolved_vars[from_stage][from_var]

            elif var_type == "choice":
                result[var_name] = rng.choice(var_def["values"])

            elif var_type == "filename":
                result[var_name] = rng.choice(var_def["name_pool"])

            elif var_type == "fixed":
                result[var_name] = var_def["value"]

            elif var_type == "subset":
                count = rng.randint(var_def["min_count"], var_def["max_count"])
                selected = rng.sample(var_def["all_values"], count)
                result[var_name] = ", ".join(selected)

            elif var_type == "path":
                subdir = rng.choice(var_def["subdir_pool"])
                result[var_name] = f"{var_def['base']}\\{subdir}"

            else:
                raise ValueError(
                    f"Unknown variable type '{var_type}' for variable "
                    f"'{var_name}' in stage {stage['index']}"
                )
        return result
