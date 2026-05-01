"""Deterministic picker for fragments.json -> attack variations.

Given a fragments JSON file (e.g. ``results/promptsteal_fragments.json``),
a seed integer, and a style string, return the ordered list of fragment
prompts that compose one attack variation. No randomness, no global state:
the same ``(file, seed, style)`` triple always produces the same output.

Used by ``attack_runner.py`` and tests; the function is also importable
from notebooks/scripts.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


__all__ = [
    "PickedFragment",
    "PickedAttack",
    "pick_attack",
    "list_seeds",
    "list_styles",
]


@dataclass(frozen=True)
class PickedFragment:
    """One fragment of a picked attack, in the chosen style."""

    index: int
    prompt: str
    style: str
    parent_prompt: str
    parent_tactic: str
    role: str
    produces: tuple[str, ...] = field(default_factory=tuple)
    consumes: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "prompt": self.prompt,
            "style": self.style,
            "parent_prompt": self.parent_prompt,
            "parent_tactic": self.parent_tactic,
            "role": self.role,
            "produces": list(self.produces),
            "consumes": list(self.consumes),
        }


@dataclass(frozen=True)
class PickedAttack:
    """One attack variation: an ordered list of style-resolved fragments."""

    seed: int
    style: str
    campaign: str
    campaign_id: str
    metadata: dict[str, Any]
    fragments: tuple[PickedFragment, ...]
    artifact_chain: dict[str, dict[str, Any]]
    fragments_path: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "seed": self.seed,
            "style": self.style,
            "campaign": self.campaign,
            "campaign_id": self.campaign_id,
            "metadata": dict(self.metadata),
            "fragments": [f.to_dict() for f in self.fragments],
            "artifact_chain": dict(self.artifact_chain),
            "fragments_path": self.fragments_path,
        }


def _load_doc(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Fragments file not found: {p}")
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {p}: {exc}") from exc
    if not isinstance(doc, dict) or "variations" not in doc:
        raise ValueError(f"Expected top-level 'variations' array in {p}")
    return doc


def _find_variation(doc: dict[str, Any], seed: int) -> dict[str, Any]:
    for v in doc.get("variations", []):
        if isinstance(v, dict) and int(v.get("seed", -1)) == int(seed):
            return v
    available = [int(v.get("seed", -1)) for v in doc.get("variations", []) if isinstance(v, dict)]
    raise KeyError(
        f"seed={seed} not present in fragments file (available: {available[:10]}"
        f"{'...' if len(available) > 10 else ''})"
    )


def _pick_style_prompt(fragment: dict[str, Any], style: str) -> str:
    for v in fragment.get("variations", []):
        if isinstance(v, dict) and str(v.get("style", "")) == style:
            prompt = v.get("prompt")
            if not isinstance(prompt, str) or not prompt.strip():
                raise ValueError(
                    f"Fragment {fragment.get('fragment_index')} has empty prompt for style={style!r}"
                )
            return prompt
    available_styles = [str(v.get("style")) for v in fragment.get("variations", []) if isinstance(v, dict)]
    raise KeyError(
        f"style={style!r} missing on fragment_index={fragment.get('fragment_index')} "
        f"(available: {available_styles})"
    )


def pick_attack(
    fragments_path: str | Path,
    seed: int,
    style: str = "direct",
) -> PickedAttack:
    """Deterministically pick one attack variation in a single style.

    Returns a :class:`PickedAttack` with one :class:`PickedFragment` per
    fragment in ``fragment_index`` order.

    Raises:
        FileNotFoundError: ``fragments_path`` does not exist.
        ValueError: file is not a valid fragments JSON document.
        KeyError: ``seed`` not present, or ``style`` missing on any fragment.
    """
    doc = _load_doc(fragments_path)
    variation = _find_variation(doc, seed)

    raw_fragments = variation.get("fragments")
    if not isinstance(raw_fragments, list) or not raw_fragments:
        raise ValueError(f"variation seed={seed} has no fragments")

    sorted_fragments = sorted(
        (f for f in raw_fragments if isinstance(f, dict)),
        key=lambda f: int(f.get("fragment_index", 0)),
    )

    picked: list[PickedFragment] = []
    for frag in sorted_fragments:
        idx = int(frag.get("fragment_index", len(picked)))
        prompt = _pick_style_prompt(frag, style)
        produces = tuple(str(x) for x in frag.get("produces", []) or [])
        consumes = tuple(str(x) for x in frag.get("consumes", []) or [])
        picked.append(
            PickedFragment(
                index=idx,
                prompt=prompt,
                style=style,
                parent_prompt=str(frag.get("parent_prompt") or ""),
                parent_tactic=str(frag.get("parent_tactic") or ""),
                role=str(frag.get("role") or ""),
                produces=produces,
                consumes=consumes,
            )
        )

    metadata = dict(variation.get("metadata") or {})
    campaign_id = str(variation.get("campaign_id") or metadata.get("id") or f"SEED_{seed}")
    campaign = str(doc.get("campaign") or metadata.get("id") or "unknown").lower()
    artifact_chain = dict(variation.get("artifact_chain") or {})

    return PickedAttack(
        seed=int(seed),
        style=style,
        campaign=campaign,
        campaign_id=campaign_id,
        metadata=metadata,
        fragments=tuple(picked),
        artifact_chain=artifact_chain,
        fragments_path=str(Path(fragments_path).resolve()),
    )


def list_seeds(fragments_path: str | Path) -> list[int]:
    """Return all seeds present in the fragments file, in source order."""
    doc = _load_doc(fragments_path)
    return [
        int(v.get("seed", -1))
        for v in doc.get("variations", [])
        if isinstance(v, dict) and "seed" in v
    ]


def list_styles(fragments_path: str | Path, seed: int | None = None) -> list[str]:
    """Return the styles available for ``seed`` (defaults to first variation).

    All seeds in a properly-generated file have the same style set; we
    return styles from the first or specified variation.
    """
    doc = _load_doc(fragments_path)
    variations = doc.get("variations") or []
    if not variations:
        return []
    if seed is None:
        target = variations[0]
    else:
        target = _find_variation(doc, seed)
    fragments = target.get("fragments") or []
    if not fragments:
        return []
    seen: list[str] = []
    for v in fragments[0].get("variations", []) or []:
        if isinstance(v, dict):
            s = str(v.get("style") or "")
            if s and s not in seen:
                seen.append(s)
    return seen
