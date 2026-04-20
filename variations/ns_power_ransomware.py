"""
NS_POWER_RANSOMWARE campaign variation generator.

Generates deterministic variations of the Nova Scotia Power ransomware
campaign, including initial access, discovery, collection, exfiltration,
encryption, and post-breach monetization steps.
"""

import json
import random
from pathlib import Path
from typing import Any, Dict, List, Tuple

try:
    from variations.base import BaseVariation, MitreType
except ModuleNotFoundError:
    from base import BaseVariation, MitreType  # type: ignore[no-redef]


class NsPowerRansomwareVariation(BaseVariation):
    """Deterministic generator for the NS Power ransomware campaign."""

    def __init__(self, seed_file: str = "seeds/ns_power_ransomware.json"):
        with open(seed_file) as f:
            self.data = json.load(f)
        self._validate_seed_tactics(self.data)

    def make_variation(self, seed: int) -> List[Tuple[str, MitreType]]:
        rng = random.Random(seed)
        dimension_choices = self._select_dimensions(rng)
        stages = self.data["attack_stages"]
        resolved_vars: Dict[int, Dict[str, Any]] = {}

        result = []
        for stage in stages:
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
        stages = self.data["attack_stages"]
        resolved_vars: Dict[int, Dict[str, Any]] = {}

        result = []
        for stage in stages:
            stage_vars = self._resolve_variables(
                stage, rng, resolved_vars, dimension_choices
            )
            prompt = stage["baseline_prompt"].format(**stage_vars)
            resolved_vars[stage["index"]] = stage_vars
            result.append(
                {
                    "index": stage["index"],
                    "prompt": prompt,
                    "mitre_tactic": stage["mitre_tactic"],
                    "mitre_technique": stage["mitre_technique"],
                    "mitre_technique_name": stage["mitre_technique_name"],
                    "description": stage["description"],
                    "resolved_variables": dict(stage_vars),
                    "dimension_choices": dict(dimension_choices),
                }
            )

        return result



if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Generate NS Power ransomware campaign variations"
    )
    parser.add_argument(
        "--seed-file",
        default="seeds/ns_power_ransomware.json",
        help="Path to seed JSON file",
    )
    parser.add_argument(
        "--seed", type=int, default=42, help="Random seed for variation generation"
    )
    parser.add_argument(
        "--count",
        type=int,
        default=1,
        help="Number of variations to generate (seeds 0..count-1)",
    )
    parser.add_argument(
        "--detailed", action="store_true", help="Print detailed output with metadata"
    )
    parser.add_argument(
        "--output", type=str, default=None, help="Write JSON output to file"
    )
    args = parser.parse_args()

    try:
        gen = NsPowerRansomwareVariation(args.seed_file)
    except FileNotFoundError:
        print(f"Error: seed file not found: {args.seed_file}", file=sys.stderr)
        sys.exit(1)

    all_variations = []
    seeds = range(args.count) if args.count > 1 else [args.seed]

    for s in seeds:
        print(f"\n{'=' * 70}")
        print(f"  NS_POWER_RANSOMWARE Variation — seed={s}")
        print(f"{'=' * 70}")

        if args.detailed:
            variation = gen.make_variation_detailed(s)
            for stage in variation:
                print(f"\n  Stage {stage['index']} [{stage['mitre_tactic']}]")
                print(
                    f"  Technique: {stage['mitre_technique']} — {stage['mitre_technique_name']}"
                )
                print(
                    f"  Variables: {json.dumps(stage['resolved_variables'], indent=4)}"
                )
                print(f"  Prompt: {stage['prompt']}")
            all_variations.append({"seed": s, "stages": variation})
        else:
            variation = gen.make_variation(s)
            for prompt, tactic in variation:
                print(f"\n  [{tactic}] {prompt}")
            all_variations.append(
                {
                    "seed": s,
                    "stages": [{"prompt": p, "mitre_tactic": t} for p, t in variation],
                }
            )

    if args.output:
        output_data = {
            "campaign_id": "ns_power_ransomware",
            "metadata": gen.data["metadata"],
            "variations": all_variations,
        }
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(output_data, f, indent=2)
        print(f"\nJSON output written to: {args.output}")
