"""
MALTERMINAL Campaign — make_variation implementation.

Generates deterministic variations of the MalTerminal kill chain where
OpenAI GPT-4 is queried at runtime to generate ransomware or reverse shell
Python code, executed via exec() with no static payload in the binary.

Usage:
    from variations.malterminal import MalTerminalVariation

    gen = MalTerminalVariation("seeds/malterminal.json")
    variation = gen.make_variation(seed=42)
    for prompt, tactic in variation:
        print(f"[{tactic}] {prompt}")
"""

import json
import random
from pathlib import Path
from typing import Any, Dict, List, Tuple

from variations.base import BaseVariation, MitreType


class MalTerminalVariation(BaseVariation):
    """
    Custom make_variation for MalTerminal campaign.

    Deterministic: same seed always produces the same output.
    No remote LLM calls — pure Python string formatting.
    """

    def __init__(self, seed_file: str = "seeds/malterminal.json"):
        with open(seed_file) as f:
            self.data = json.load(f)
        self._validate_seed_tactics(self.data)

    def _select_dimensions(self, rng: random.Random) -> Dict[str, str]:
        """Select one value per variation dimension using the seeded RNG."""
        dimensions = self.data.get("variation_dimensions", {})
        return {
            name: rng.choice(dim["values"])
            for name, dim in dimensions.items()
        }

    def make_variation(self, seed: int) -> List[Tuple[str, MitreType]]:
        """
        Generate one deterministic variation of the full MalTerminal kill chain.

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

    def _resolve_variables(
        self,
        stage: dict,
        rng: random.Random,
        resolved_vars: Dict[int, Dict[str, Any]],
        dimension_choices: Dict[str, str],
    ) -> Dict[str, Any]:
        """Resolve all variables for a stage, handling inheritance and types."""
        result = {}
        variables = stage.get("variables", {})

        for var_name, var_def in variables.items():
            var_type = var_def["type"]

            if var_type == "inherit":
                from_stage = var_def["from_stage"]
                from_var = var_def["variable"]
                result[var_name] = resolved_vars[from_stage][from_var]

            elif var_type == "fixed":
                result[var_name] = var_def["value"]

            elif var_type == "choice":
                result[var_name] = rng.choice(var_def["values"])

            elif var_type == "subset":
                count = rng.randint(var_def["min_count"], var_def["max_count"])
                selected = rng.sample(var_def["all_values"], count)
                result[var_name] = ", ".join(selected)

            elif var_type == "path":
                subdir = rng.choice(var_def["subdir_pool"])
                result[var_name] = f"{var_def['base']}\\{subdir}"

            elif var_type == "filename":
                result[var_name] = rng.choice(var_def["name_pool"])

            elif var_type == "dimension_driven":
                dimension = var_def["dimension"]
                chosen_value = dimension_choices[dimension]
                lookup = var_def["values_by_dimension"]
                result[var_name] = lookup[chosen_value]

            elif var_type == "ipv4":
                result[var_name] = (
                    f"10.{rng.randint(0, 255)}"
                    f".{rng.randint(0, 255)}"
                    f".{rng.randint(1, 254)}"
                )

            elif var_type == "port":
                result[var_name] = rng.choice(var_def["range"])

            else:
                raise ValueError(
                    f"Unknown variable type '{var_type}' for variable '{var_name}' "
                    f"in stage {stage['index']}"
                )

        return result


# ---------------------------------------------------------------------------
# CLI: run standalone to inspect variations
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Generate MalTerminal campaign variations"
    )
    parser.add_argument(
        "--seed-file",
        default="seeds/malterminal.json",
        help="Path to seed JSON file",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
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
        gen = MalTerminalVariation(args.seed_file)
    except FileNotFoundError:
        print(f"Error: seed file not found: {args.seed_file}", file=sys.stderr)
        sys.exit(1)

    all_variations = []
    seeds = range(args.count) if args.count > 1 else [args.seed]

    for s in seeds:
        print(f"\n{'='*70}")
        print(f"  MALTERMINAL Variation — seed={s}")
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
            "campaign_id": "MALTERMINAL",
            "metadata": gen.data["metadata"],
            "variations": all_variations,
        }
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(output_data, f, indent=2)
        print(f"\nJSON output written to: {args.output}")
