"""
AI-Driven Phishing Campaign — AIPhishingVariation implementation.

Generates deterministic variations of the AI-enhanced phishing kill chain
based on the Microsoft Digital Defense Report 2025 intelligence.

Usage:
    from variations.ai_phishing import AIPhishingVariation

    gen = AIPhishingVariation("seeds/ai-phishing.json")
    variation = gen.make_variation(seed=42)
    for prompt, tactic in variation:
        print(f"[{tactic}] {prompt}")

Example usage from CLI:
    uv run variations/ai_phishing.py --seed-file seeds/ai-phishing.json --seed 42 --detailed --output resutls/ai_phishing_variation_42.json
"""

import json
import random
from pathlib import Path
from typing import Any, Dict, List, Tuple


class AIPhishingVariation:
    """
    Custom make_variation for AI-Driven Phishing campaign.

    Deterministic: same seed always produces the same output.
    """

    def __init__(self, seed_file: str = "seeds/ai-phishing.json"):
        with open(seed_file) as f:
            self.data = json.load(f)

    def make_variation(self, seed: int) -> List[Tuple[str, str]]:
        """
        Generate one deterministic variation of the full AI-Phishing kill chain.

        Args:
            seed: Integer seed for deterministic randomness.

        Returns:
            List of (prompt_text, mitre_tactic) tuples — one per attack stage.
        """
        rng = random.Random(seed)
        stages = self.data["attack_stages"]
        resolved_vars: Dict[int, Dict[str, Any]] = {}
        cumulative_vars: Dict[str, Any] = {}

        result = []
        for stage in stages:
            stage_vars = self._resolve_variables(stage, rng, resolved_vars)
            cumulative_vars.update(stage_vars)
            prompt = stage["baseline_prompt"].format(**cumulative_vars)
            resolved_vars[stage["index"]] = stage_vars
            result.append((prompt, stage["mitre_tactic"]))

        return result

    def make_variation_detailed(self, seed: int) -> List[Dict[str, Any]]:
        """
        Generate a detailed variation with full metadata per stage.

        Returns list of dicts with: prompt, tactic, technique, description,
        resolved_variables — useful for debugging and JSON export.
        """
        rng = random.Random(seed)
        stages = self.data["attack_stages"]
        resolved_vars: Dict[int, Dict[str, Any]] = {}
        cumulative_vars: Dict[str, Any] = {}

        result = []
        for stage in stages:
            stage_vars = self._resolve_variables(stage, rng, resolved_vars)
            cumulative_vars.update(stage_vars)
            prompt = stage["baseline_prompt"].format(**cumulative_vars)
            resolved_vars[stage["index"]] = stage_vars
            result.append({
                "index": stage["index"],
                "prompt": prompt,
                "mitre_tactic": stage["mitre_tactic"],
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
                all_vals = var_def.get("values") or var_def.get("all_values")
                min_c = var_def.get("min_count", 1)
                max_c = var_def.get("max_count", len(all_vals))
                count = rng.randint(min_c, max_c)
                selected = rng.sample(all_vals, count)
                result[var_name] = ", ".join(selected)

            elif var_type == "path":
                if "values" in var_def:
                    result[var_name] = rng.choice(var_def["values"])
                else:
                    base = var_def.get("base", "/tmp")
                    subdir = rng.choice(var_def.get("subdir_pool", ["cache", "tmp"]))
                    result[var_name] = f"{base}/{subdir}"

            elif var_type == "filename":
                result[var_name] = rng.choice(var_def["values"] or var_def["name_pool"])

            elif var_type == "ipv4":
                if "values" in var_def:
                    result[var_name] = rng.choice(var_def["values"])
                else:
                    result[var_name] = (
                        f"10.{rng.randint(0, 255)}"
                        f".{rng.randint(0, 255)}"
                        f".{rng.randint(1, 254)}"
                    )

            elif var_type == "port":
                if "values" in var_def:
                    result[var_name] = rng.choice(var_def["values"])
                else:
                    result[var_name] = rng.choice(var_def.get("range", ["443", "80", "8080"]))

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
        description="Generate AI-Phishing campaign variations"
    )
    parser.add_argument(
        "--seed-file",
        default="seeds/ai-phishing.json",
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
        gen = AIPhishingVariation(args.seed_file)
    except FileNotFoundError:
        print(f"Error: seed file not found: {args.seed_file}", file=sys.stderr)
        sys.exit(1)

    all_variations = []
    seeds = range(args.count) if args.count > 1 else [args.seed]

    for s in seeds:
        print(f"\n{'='*70}")
        print(f"  AI-PHISHING Variation — seed={s}")
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
            "campaign_id": "AI-PHISH-2025",
            "metadata": gen.data["metadata"],
            "variations": all_variations,
        }
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(output_data, f, indent=2)
        print(f"\nJSON output written to: {args.output}")
