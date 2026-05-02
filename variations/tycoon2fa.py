"""
TYCOON2FA Campaign — make_variation implementation.

Generates deterministic variations of the Tycoon2FA / Storm-1747
phishing-as-a-service kill chain sourced from Microsoft's 2026-03
disruption blog and the AI-threat ecosystem post. The kit ships an
admin panel, brand-themed sign-in templates (Microsoft 365, Outlook,
SharePoint, OneDrive), short-lived rotating infrastructure with
redirect chains via Cloudflare/Azure Blob/Firebase/Wix/TikTok,
custom CAPTCHA and fingerprinting gates, and an adversary-in-the-
middle relay that forwards captured credentials, MFA codes, and
session cookies to a Telegram operator channel.
"""

import json
import random
from typing import Any, Dict, List, Tuple

from variations.base import BaseVariation, MitreType


class Tycoon2FAVariation(BaseVariation):
    """Variation generator for TYCOON2FA campaign."""

    def __init__(self, seed_file: str = "seeds/tycoon2fa.json"):
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
