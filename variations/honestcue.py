"""
HONESTCUE Campaign — make_variation implementation.

Generates deterministic variations of the HONESTCUE kill chain where
Gemini API generates a C# second-stage payload at runtime, compiled
in-memory via CSharpCodeProvider with zero disk artifacts.

Usage:
    from variations.honestcue import HonestCueVariation

    gen = HonestCueVariation("seeds/honestcue.json")
    variation = gen.make_variation(seed=13)
    for prompt, tactic in variation:
        print(f"[{tactic}] {prompt}")
"""

import json
import random
from pathlib import Path
from typing import Any, Dict, List, Tuple

from variations.base import BaseVariation, MitreType


class HonestCueVariation(BaseVariation):
    """
    Custom make_variation for HONESTCUE campaign.

    Deterministic: same seed always produces the same output.
    No remote LLM calls — pure Python string formatting.
    """

    def __init__(self, seed_file: str = "seeds/honestcue.json"):
        with open(seed_file) as f:
            self.data = json.load(f)
        self._validate_seed_tactics(self.data)

    def make_variation(self, seed: int) -> List[Tuple[str, MitreType]]:
        """
        Generate one deterministic variation of the full HONESTCUE kill chain.

        Args:
            seed: Integer seed for deterministic randomness.

        Returns:
            List of (prompt_text, MitreType) tuples — one per attack stage.
        """
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
        """
        Generate a detailed variation with full metadata per stage.

        Returns list of dicts with: prompt, tactic, technique, description,
        resolved_variables — useful for debugging and JSON export.
        """
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
            stage_dict: Dict[str, Any] = {
                "index": stage["index"],
                "prompt": prompt,
                "mitre_tactic": stage["mitre_tactic"],
                "mitre_technique": stage["mitre_technique"],
                "mitre_technique_name": stage["mitre_technique_name"],
                "description": stage["description"],
                "resolved_variables": stage_vars,
                "dimension_choices": dimension_choices,
            }

            if "fragments" in stage:
                stage_dict["fragments"] = [
                    {
                        "role": frag["role"],
                        "prompt": frag["prompt"].format(**stage_vars),
                        "produces": list(frag.get("produces", [])),
                        "consumes": list(frag.get("consumes", [])),
                    }
                    for frag in stage["fragments"]
                ]

            result.append(stage_dict)

        return result


# ---------------------------------------------------------------------------
# CLI: run standalone to inspect variations
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Generate HONESTCUE campaign variations"
    )
    parser.add_argument(
        "--seed-file",
        default="seeds/honestcue.json",
        help="Path to seed JSON file",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=13,
        help="Random seed for variation generation",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=1,
        help="Number of variations to generate (seeds 0..count-1)",
    )
    parser.add_argument(
        "--detailed",
        action="store_true",
        help="Print detailed output with metadata",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Write JSON output to file",
    )
    args = parser.parse_args()

    try:
        gen = HonestCueVariation(args.seed_file)
    except FileNotFoundError:
        print(f"Error: seed file not found: {args.seed_file}", file=sys.stderr)
        sys.exit(1)

    all_variations = []
    seeds = range(args.count) if args.count > 1 else [args.seed]

    for s in seeds:
        print(f"\n{'='*70}")
        print(f"  HONESTCUE Variation — seed={s}")
        print(f"{'='*70}")

        if args.detailed:
            variation = gen.make_variation_detailed(s)
            for stage in variation:
                print(f"\n  Stage {stage['index']} [{stage['mitre_tactic']}]")
                print(f"  Technique: {stage['mitre_technique']} — {stage['mitre_technique_name']}")
                print(f"  Variables: {json.dumps(stage['resolved_variables'], indent=4)}")
                print(f"  Prompt: {stage['prompt']}")
            all_variations.append({"seed": s, "stages": variation})
        else:
            variation = gen.make_variation(s)
            for prompt, tactic in variation:
                print(f"\n  [{tactic}] {prompt}")
            all_variations.append({
                "seed": s,
                "stages": [{"prompt": p, "mitre_tactic": t} for p, t in variation],
            })

    if args.output:
        output_data = {
            "campaign_id": "HONESTCUE",
            "metadata": gen.data["metadata"],
            "variations": all_variations,
        }
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(output_data, f, indent=2)
        print(f"\nJSON output written to: {args.output}")
