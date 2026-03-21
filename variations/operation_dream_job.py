"""
UNC2970 / Lazarus Group — Operation Dream Job (AI-Assisted Variant).

Generates deterministic variations of the Operation Dream Job kill chain where
DPRK threat actors use Gemini to synthesize OSINT and build high-fidelity
recruiter personas targeting defense and cybersecurity sector employees. Fake
LinkedIn recruiters deliver trojanized hiring artifacts (trojanized PDF readers,
ISO-based VNC assessments, or Word documents with remote template injection)
after establishing rapport.

Sources:
    GTIG — "Distillation, Experimentation, and Integration of AI for
            Adversarial Use" (Feb 12, 2026)
    Mandiant — "An Offer You Can Refuse: UNC2970 Backdoor Deployment
                Using Trojanized PDF Reader" (Sept 26, 2024)
    Mandiant — "UNC2970: Operation Dream Job" (Mar 2023)
    ESET — "Operation DreamJob: European Defense Targeting" (Oct 2025)

Usage:
    from variations.operation_dream_job import OperationDreamJobVariation

    gen = OperationDreamJobVariation("seeds/operation_dream_job.json")
    variation = gen.make_variation(seed=13)
    for prompt, tactic in variation:
        print(f"[{tactic}] {prompt}")
"""

import json
import random
from pathlib import Path
from typing import Any, Dict, List, Tuple

try:
    from variations.base import BaseVariation, MitreType
except ModuleNotFoundError:
    from base import BaseVariation, MitreType  # type: ignore[no-redef]


class OperationDreamJobVariation(BaseVariation):
    """
    Custom make_variation for the UNC2970 Operation Dream Job campaign.

    Deterministic: same seed always produces the same output.
    No remote LLM calls — pure Python string formatting.

    Supported variable types for this campaign include two custom types:
        fake_recruiter_name — plausible professional full name (First Last)
        fake_firm_name      — plausible defense/security recruiting firm name
    """

    def __init__(self, seed_file: str = "seeds/operation_dream_job.json"):
        with open(seed_file) as f:
            self.data = json.load(f)
        self._validate_seed_tactics(self.data)

    def _select_dimensions(self, rng: random.Random) -> Dict[str, str]:
        """Select one value per variation dimension using the seeded RNG."""
        dimensions = self.data.get("variation_dimensions", {})
        return {
            name: rng.choice(dimensions[name]["values"])
            for name in sorted(dimensions)
        }

    def make_variation(self, seed: int) -> List[Tuple[str, MitreType]]:
        """
        Generate one deterministic variation of the full Operation Dream Job kill chain.

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
        resolved_variables, dimension_choices — useful for debugging and JSON export.
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
                "mitre_tactic": self._coerce_tactic(stage["mitre_tactic"]),
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
        """Resolve all variables for a stage, handling all supported types."""
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

            elif var_type == "dimension_driven":
                dimension = var_def["dimension"]
                chosen_value = dimension_choices[dimension]
                lookup = var_def["values_by_dimension"]
                result[var_name] = lookup[chosen_value]

            elif var_type == "integer_range":
                result[var_name] = rng.randint(var_def["min"], var_def["max"])

            elif var_type == "fake_recruiter_name":
                # Generate a plausible US professional full name.
                # Mirrors the documented UNC2970 pattern of maintaining
                # "specially crafted LinkedIn accounts based on legitimate users"
                # (Mandiant Mar 2023). Not a real person.
                first_names = [
                    "Sarah", "Michael", "Jennifer", "David", "Emily",
                    "James", "Amanda", "Robert", "Jessica", "William",
                    "Ashley", "Christopher", "Lauren", "Daniel", "Megan",
                    "Matthew", "Rachel", "Andrew", "Stephanie", "Kevin",
                ]
                last_names = [
                    "Chen", "Rodriguez", "Williams", "Johnson", "Mitchell",
                    "Anderson", "Taylor", "Thompson", "Martinez", "Harris",
                    "Clark", "Lewis", "Walker", "Hall", "Allen",
                    "Young", "King", "Wright", "Scott", "Green",
                ]
                result[var_name] = (
                    f"{rng.choice(first_names)} {rng.choice(last_names)}"
                )

            elif var_type == "fake_firm_name":
                # Generate a plausible fake defense/security recruiting firm name.
                # UNC2970 uses both real company impersonation (NYT, BAE Systems)
                # and fictitious firm names (Mandiant Sept 2024). This type
                # generates the fictitious-firm pattern.
                prefixes = [
                    "Apex", "Meridian", "Vanguard", "Sentinel", "Sterling",
                    "Atlas", "Pinnacle", "Nexus", "Keystone", "Strategos",
                ]
                suffixes = [
                    "Talent Group", "Executive Search", "Defense Solutions",
                    "Partners", "Associates", "Advisors", "Search Group",
                ]
                result[var_name] = (
                    f"{rng.choice(prefixes)} {rng.choice(suffixes)}"
                )

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
        description="Generate UNC2970 Operation Dream Job campaign variations"
    )
    parser.add_argument(
        "--seed-file",
        default="seeds/operation_dream_job.json",
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
        gen = OperationDreamJobVariation(args.seed_file)
    except FileNotFoundError:
        print(f"Error: seed file not found: {args.seed_file}", file=sys.stderr)
        sys.exit(1)

    all_variations = []
    seeds = range(args.count) if args.count > 1 else [args.seed]

    for s in seeds:
        print(f"\n{'='*70}")
        print(f"  Operation Dream Job Variation — seed={s}")
        print(f"{'='*70}")

        if args.detailed:
            variation = gen.make_variation_detailed(s)
            for stage in variation:
                print(f"\n  Stage {stage['index']} [{stage['mitre_tactic']}]")
                print(f"  Technique: {stage['mitre_technique']} — {stage['mitre_technique_name']}")
                print(f"  Dimensions: {json.dumps(stage['dimension_choices'], indent=4)}")
                print(f"  Variables: {json.dumps(stage['resolved_variables'], indent=4)}")
                print(f"  Prompt:\n    {stage['prompt']}")
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
            "campaign_id": "UNC2970_OPERATION_DREAM_JOB",
            "metadata": gen.data["metadata"],
            "variations": all_variations,
        }
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(output_data, f, indent=2)
        print(f"\nJSON output written to: {args.output}")
