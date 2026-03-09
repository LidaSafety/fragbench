"""
Model harness — load attack specs and run variations against Qwen or Claude.

Usage:
    runner = QwenRunner(api_key="...", model="qwen3.5-35b-a3b")
    # or
    runner = ClaudeRunner(api_key="...")

    spec = load_attack("attacks/quietvault.toml")
    result = runner.run_variation(spec.fragments[0].variations[2])
"""

from __future__ import annotations

import sys
import tomllib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Data models (plain dataclasses — no pydantic dependency)
# ---------------------------------------------------------------------------

@dataclass
class Variation:
    style: str
    prompt: str


@dataclass
class Fragment:
    index: int
    description: str
    variations: list[Variation] = field(default_factory=list)


@dataclass
class AttackMetadata:
    id: str
    technique: str
    technique_name: str
    description: str
    tags: list[str] = field(default_factory=list)


@dataclass
class AttackSpec:
    metadata: AttackMetadata
    fragments: list[Fragment]


@dataclass
class VariationResult:
    campaign_id: str
    fragment_index: int
    style: str
    prompt: str
    response: str
    model: str
    error: str | None = None


# ---------------------------------------------------------------------------
# TOML loader
# ---------------------------------------------------------------------------

def load_attack(path: str | Path) -> AttackSpec:
    """Parse a campaign TOML file into an AttackSpec."""
    data = tomllib.loads(Path(path).read_text())
    meta = data["metadata"]
    metadata = AttackMetadata(
        id=meta["id"],
        technique=meta["technique"],
        technique_name=meta["technique_name"],
        description=meta["description"],
        tags=meta.get("tags", []),
    )
    fragments = []
    for frag_data in data.get("fragments", []):
        variations = [
            Variation(style=v["style"], prompt=v["prompt"])
            for v in frag_data.get("variations", [])
        ]
        fragments.append(Fragment(
            index=frag_data["index"],
            description=frag_data["description"],
            variations=variations,
        ))
    return AttackSpec(metadata=metadata, fragments=fragments)


def load_all_attacks(attacks_dir: str | Path = "attacks") -> list[AttackSpec]:
    """Load all *.toml files from the attacks directory."""
    attacks_dir = Path(attacks_dir)
    specs = []
    for toml_file in sorted(attacks_dir.glob("*.toml")):
        specs.append(load_attack(toml_file))
    return specs


# ---------------------------------------------------------------------------
# Base runner
# ---------------------------------------------------------------------------

class ModelRunner(ABC):
    """Abstract base for model runners."""

    @abstractmethod
    def run_variation(self, variation: Variation, campaign_id: str = "", fragment_index: int = 0) -> VariationResult:
        """Send a variation prompt to the model and return the response."""
        ...

    def run_fragment(self, spec: AttackSpec, fragment_index: int = 0) -> list[VariationResult]:
        """Run all variations for a fragment."""
        fragment = spec.fragments[fragment_index]
        results = []
        for variation in fragment.variations:
            result = self.run_variation(
                variation,
                campaign_id=spec.metadata.id,
                fragment_index=fragment_index,
            )
            results.append(result)
        return results

    def run_attack(self, spec: AttackSpec) -> list[VariationResult]:
        """Run all fragments × all variations for an attack spec."""
        results = []
        for i in range(len(spec.fragments)):
            results.extend(self.run_fragment(spec, i))
        return results


# ---------------------------------------------------------------------------
# Qwen runner (DashScope OpenAI-compatible API)
# ---------------------------------------------------------------------------

class QwenRunner(ModelRunner):
    """
    Sends prompts to Qwen via DashScope's OpenAI-compatible endpoint.
    Set DASHSCOPE_API_KEY in environment or pass api_key explicitly.
    """

    DEFAULT_MODEL = "qwen-plus"
    BASE_URL = "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"

    def __init__(
        self,
        api_key: str | None = None,
        model: str = DEFAULT_MODEL,
        max_tokens: int = 2048,
        temperature: float = 0.7,
        enable_thinking: bool = False,
    ) -> None:
        import os
        try:
            from openai import OpenAI
        except ImportError:
            print("openai package required for QwenRunner: pip install openai", file=sys.stderr)
            raise

        self._model = model
        self._max_tokens = max_tokens
        self._temperature = temperature
        self._enable_thinking = enable_thinking
        self._client = OpenAI(
            api_key=api_key or os.environ["DASHSCOPE_API_KEY"],
            base_url=self.BASE_URL,
        )

    def run_variation(self, variation: Variation, campaign_id: str = "", fragment_index: int = 0) -> VariationResult:
        extra: dict[str, Any] = {}
        if self._enable_thinking:
            extra["extra_body"] = {"enable_thinking": True}

        try:
            completion = self._client.chat.completions.create(
                model=self._model,
                messages=[{"role": "user", "content": variation.prompt}],
                max_tokens=self._max_tokens,
                temperature=self._temperature,
                **extra,
            )
            response = completion.choices[0].message.content or ""
            error = None
        except Exception as exc:
            response = ""
            error = str(exc)

        return VariationResult(
            campaign_id=campaign_id,
            fragment_index=fragment_index,
            style=variation.style,
            prompt=variation.prompt,
            response=response,
            model=self._model,
            error=error,
        )


# ---------------------------------------------------------------------------
# Claude runner (Anthropic SDK)
# ---------------------------------------------------------------------------

class ClaudeRunner(ModelRunner):
    """
    Sends prompts to Claude via the Anthropic SDK.
    Set ANTHROPIC_API_KEY in environment or pass api_key explicitly.
    """

    DEFAULT_MODEL = "claude-sonnet-4-6"

    def __init__(
        self,
        api_key: str | None = None,
        model: str = DEFAULT_MODEL,
        max_tokens: int = 2048,
        extended_thinking: bool = False,
    ) -> None:
        import os
        try:
            import anthropic
        except ImportError:
            print("anthropic package required for ClaudeRunner: pip install anthropic", file=sys.stderr)
            raise

        self._model = model
        self._max_tokens = max_tokens
        self._extended_thinking = extended_thinking
        self._client = anthropic.Anthropic(
            api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"),
        )

    def run_variation(self, variation: Variation, campaign_id: str = "", fragment_index: int = 0) -> VariationResult:
        import anthropic

        kwargs: dict[str, Any] = dict(
            model=self._model,
            max_tokens=self._max_tokens,
            messages=[{"role": "user", "content": variation.prompt}],
        )
        if self._extended_thinking:
            kwargs["thinking"] = {"type": "adaptive"}
            kwargs["temperature"] = 1
            kwargs["betas"] = ["interleaved-thinking-2025-05-14"]

        try:
            response_obj = self._client.messages.create(**kwargs)
            response = ""
            for block in response_obj.content:
                if hasattr(block, "type") and block.type == "text":
                    response += getattr(block, "text", "")
            error = None
        except Exception as exc:
            response = ""
            error = str(exc)

        return VariationResult(
            campaign_id=campaign_id,
            fragment_index=fragment_index,
            style=variation.style,
            prompt=variation.prompt,
            response=response,
            model=self._model,
            error=error,
        )
