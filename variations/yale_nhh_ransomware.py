"""
YALE_NHH_RANSOMWARE / Yale New Haven Health Ransomware Campaign (Mar 2025).

Generates deterministic variations of the YNHH kill chain where threat actors
exploit a public-facing healthcare application for initial access, deploy a
persistent implant, enumerate and move laterally across clinical/administrative
systems, dump credentials, bulk-collect 5.5M patient records, exfiltrate via
HTTPS, then deploy ransomware with double-extortion demand.

Source: Yale New Haven Health breach disclosure (Mar 2025), Entry #46

Usage:
    from variations.yale_nhh_ransomware import YaleNHHRansomwareVariation

    gen = YaleNHHRansomwareVariation("seeds/yale_nhh_ransomware.json")
    variation = gen.make_variation(seed=42)
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


# Base58 alphabet used for BTC-style addresses (no 0, O, I, l)
_BTC_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


class YaleNHHRansomwareVariation(BaseVariation):
    """
    Custom make_variation for YALE_NHH_RANSOMWARE campaign.

    Deterministic: same seed always produces the same output.
    No remote LLM calls — pure Python string formatting.

    Supports all standard variable types:
        choice         — pick one value from a list
        subset         — pick N values from all_values and join with ", "
        inherit        — copy a resolved variable from an earlier stage
        path           — construct a Windows path from base + random subdir
        filename       — pick a filename from a name pool
        ipv4           — generate a random 10.x.x.x address
        port           — pick a port from a range list
        dollar_amount  — formatted dollar figure within a range and step
        integer_range  — integer drawn uniformly from [min, max]
        crypto_wallet  — fake BTC-style Base58 address (not a real address)
    """

    def __init__(self, seed_file: str = "seeds/yale_nhh_ransomware.json"):
        with open(seed_file) as f:
            self.data = json.load(f)
        self._validate_seed_tactics(self.data)

    def make_variation(self, seed: int) -> List[Tuple[str, MitreType]]:
        """
        Generate one deterministic variation of the full YALE_NHH_RANSOMWARE kill chain.

        Args:
            seed: Integer seed for deterministic randomness.

        Returns:
            List of (prompt_text, mitre_tactic) tuples — one per attack stage.
        """
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
        """
        Generate a detailed variation with full metadata per stage.

        Returns list of dicts with: prompt, tactic, technique, description,
        resolved_variables — useful for debugging and JSON export.
        """
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

            elif var_type == "ipv4":
                result[var_name] = (
                    f"10.{rng.randint(0, 255)}"
                    f".{rng.randint(0, 255)}"
                    f".{rng.randint(1, 254)}"
                )

            elif var_type == "port":
                result[var_name] = rng.choice(var_def["range"])

            elif var_type == "dollar_amount":
                lo = var_def["range"][0]
                hi = var_def["range"][1]
                step = var_def.get("step", 1)
                num_steps = (hi - lo) // step
                amount = lo + rng.randint(0, num_steps) * step
                result[var_name] = f"{amount:,}"

            elif var_type == "integer_range":
                result[var_name] = rng.randint(var_def["min"], var_def["max"])

            elif var_type == "crypto_wallet":
                # Generate a plausible-looking but invalid BTC-style Base58 address.
                # Prefix: "1" (P2PKH) or "3" (P2SH); total length 34 characters.
                prefix = rng.choice(["1", "3"])
                body = "".join(rng.choices(_BTC_ALPHABET, k=33))
                result[var_name] = prefix + body

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
        description="Generate YALE_NHH_RANSOMWARE campaign variations"
    )
    parser.add_argument(
        "--seed-file",
        default="seeds/yale_nhh_ransomware.json",
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
        gen = YaleNHHRansomwareVariation(args.seed_file)
    except FileNotFoundError:
        print(f"Error: seed file not found: {args.seed_file}", file=sys.stderr)
        sys.exit(1)

    all_variations = []
    seeds = range(args.count) if args.count > 1 else [args.seed]

    for s in seeds:
        print(f"\n{'='*70}")
        print(f"  YALE_NHH_RANSOMWARE Variation — seed={s}")
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
            "campaign_id": "YALE_NHH_RANSOMWARE",
            "metadata": gen.data["metadata"],
            "variations": all_variations,
        }
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(output_data, f, indent=2)
        print(f"\nJSON output written to: {args.output}")
