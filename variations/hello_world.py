"""
HELLO_WORLD — minimal demo variation.

One stage: ask an agent to list Python files in a randomly chosen directory.
Used to demonstrate the seed → variation → MCP pipeline end-to-end.

Usage:
    from variations.hello_world import HelloWorldVariation

    gen = HelloWorldVariation("seeds/hello_world.json")
    prompt, tactic = gen.make_variation(seed=42)[0]
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
    """Minimal single-stage variation — demo only."""

    def __init__(self, seed_file: str = "seeds/hello_world.json"):
        with open(seed_file) as f:
            self.data = json.load(f)
        self._validate_seed_tactics(self.data)

    def make_variation(self, seed: int) -> List[Tuple[str, MitreType]]:
        rng = random.Random(seed)
        return [self._render_stage(stage, rng) for stage in self.data["attack_stages"]]

    def make_variation_detailed(self, seed: int) -> List[Dict[str, Any]]:
        rng = random.Random(seed)
        result = []
        for stage in self.data["attack_stages"]:
            prompt, tactic = self._render_stage(stage, rng)
            result.append({
                "index": stage["index"],
                "prompt": prompt,
                "mitre_tactic": tactic,
                "mitre_technique": stage["mitre_technique"],
                "mitre_technique_name": stage["mitre_technique_name"],
                "description": stage["description"],
            })
        return result

    def _render_stage(self, stage: dict, rng: random.Random) -> Tuple[str, MitreType]:
        resolved = {
            name: rng.choice(var["values"])
            for name, var in stage.get("variables", {}).items()
        }
        prompt = stage["baseline_prompt"].format(**resolved)
        return prompt, self._coerce_tactic(stage["mitre_tactic"])
