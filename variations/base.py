"""
Base classes and enumerations shared across all variation generators.
"""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Dict, List, Tuple


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
