"""
Base classes and enumerations shared across all variation generators.
"""

import random
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class MitreType(str, Enum):
    """
    MITRE ATT&CK Enterprise tactics (TA0001–TA0043).

    Inherits from str so values compare equal to plain strings and can be
    used directly in JSON serialisation and f-strings without .value.
    """
    RECONNAISSANCE      = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource_development"
    INITIAL_ACCESS      = "initial_access"
    EXECUTION           = "execution"
    PERSISTENCE         = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION     = "defense_evasion"
    CREDENTIAL_ACCESS   = "credential_access"
    DISCOVERY           = "discovery"
    LATERAL_MOVEMENT    = "lateral_movement"
    COLLECTION          = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION        = "exfiltration"
    IMPACT              = "impact"

class BaseVariation(ABC):
    """
    Abstract base class for all campaign variation generators.

    Subclasses must implement:
        make_variation(seed)          → List[(prompt, tactic)]
        make_variation_detailed(seed) → List[Dict[...]]

    Call _validate_seed_tactics(data) in __init__ after loading the seed JSON
    to catch invalid tactic strings at load time rather than at generation time.
    """

    @staticmethod
    def _validate_seed_tactics(data: Dict[str, Any]) -> None:
        """
        Validate every mitre_tactic value in a loaded seed against MitreType.

        Raises ValueError listing the offending stage index and value, plus all
        valid choices. Call this in __init__ immediately after loading the JSON.
        """
        valid = [t.value for t in MitreType]
        for stage in data.get("attack_stages", []):
            tactic = stage.get("mitre_tactic", "")
            try:
                MitreType(tactic)
            except ValueError:
                raise ValueError(
                    f"Stage {stage.get('index')}: '{tactic}' is not a valid MitreType. "
                    f"Valid values: {valid}"
                )

    @staticmethod
    def _coerce_tactic(tactic: str) -> MitreType:
        """Convert a raw tactic string to MitreType, raising ValueError if unknown."""
        return MitreType(tactic)

    def _select_dimensions(self, rng: random.Random) -> Dict[str, str]:
        """
        Select one value per variation dimension using the seeded RNG.

        Reads self.data["variation_dimensions"] — populated by the subclass
        __init__ when it loads the seed JSON. Returns an empty dict for seeds
        with no variation_dimensions (e.g. VIBE_EXTORTION).
        """
        dimensions = getattr(self, "data", {}).get("variation_dimensions", {})
        return {
            name: rng.choice(dim["values"])
            for name, dim in dimensions.items()
        }

    def _resolve_variables(
        self,
        stage: dict,
        rng: random.Random,
        resolved_vars: Dict[int, Dict[str, Any]],
        dimension_choices: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Resolve all variables for a single attack stage.

        Handles: inherit, fixed, choice, subset, path, filename,
                 dimension_driven, ipv4, port.

        Subclasses may override to add campaign-specific variable types
        (e.g. VibeExtortionVariation adds dollar_amount, integer_range,
        crypto_wallet).
        """
        result: Dict[str, Any] = {}
        for var_name, var_def in stage.get("variables", {}).items():
            var_type = var_def["type"]

            if var_type == "inherit":
                result[var_name] = resolved_vars[var_def["from_stage"]][var_def["variable"]]
            elif var_type == "fixed":
                result[var_name] = var_def["value"]
            elif var_type == "choice":
                result[var_name] = rng.choice(var_def["values"])
            elif var_type == "subset":
                count = rng.randint(var_def["min_count"], var_def["max_count"])
                result[var_name] = ", ".join(rng.sample(var_def["all_values"], count))
            elif var_type == "path":
                result[var_name] = f"{var_def['base']}\\{rng.choice(var_def['subdir_pool'])}"
            elif var_type == "filename":
                result[var_name] = rng.choice(var_def["name_pool"])
            elif var_type == "dimension_driven":
                if dimension_choices is None:
                    raise ValueError(
                        f"Variable '{var_name}' is dimension_driven but "
                        f"dimension_choices was not provided."
                    )
                result[var_name] = var_def["values_by_dimension"][
                    dimension_choices[var_def["dimension"]]
                ]
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
                    f"Unknown variable type '{var_type}' for '{var_name}' "
                    f"in stage {stage['index']}"
                )
        return result

    @abstractmethod
    def make_variation(self, seed: int) -> List[Tuple[str, MitreType]]:
        """
        Generate one deterministic variation of the full kill chain.

        Args:
            seed: Integer seed for deterministic randomness.

        Returns:
            List of (prompt_text, MitreType) tuples — one per attack stage.
        """

    @abstractmethod
    def make_variation_detailed(self, seed: int) -> List[Dict[str, Any]]:
        """
        Generate a detailed variation with full metadata per stage.

        Returns list of dicts with at minimum: prompt, mitre_tactic,
        mitre_technique, mitre_technique_name, description.
        """
