#!/usr/bin/env python3
"""Dump generation-time fragment inspection JSON.

This is a review/debug utility, not a runtime format.

It operates on the generation mid-state:
    seed -> make_variation -> make_fragment_groups -> [stylize] -> [legitimize]

and emits a JSON structure centered on:
    parent_prompt / parent_tactic / fragment_index / variations

This is intended for manual coherence inspection of fragmentation output.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from generator import (  # noqa: E402
    DEFAULT_OPENROUTER_BASE_URL,
    DEFAULT_OPENROUTER_GENERATOR_MODEL,
    FragmentGroup,
    STYLES,
    VARIATION_REGISTRY,
    legitimize_fragment,
    make_fragment_groups,
    stylize_fragment_group,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Dump fragment inspection JSON from the generation mid-state."
    )
    parser.add_argument(
        "--seed-file",
        required=True,
        help="Path to a seed JSON file in seeds/.",
    )
    parser.add_argument(
        "--num-variations",
        type=int,
        default=1,
        help="Number of variations to generate (default: 1).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Base seed for generation (default: random).",
    )
    parser.add_argument(
        "--fragment",
        action="store_true",
        help="Apply fragmentation before dumping inspection JSON.",
    )
    parser.add_argument(
        "--stylize",
        action="store_true",
        help="Apply style variation before dumping inspection JSON.",
    )
    parser.add_argument(
        "--styles",
        default="direct",
        help="Comma-separated styles to generate (default: direct).",
    )
    parser.add_argument(
        "--legitimize",
        action="store_true",
        help="Apply legitimization after stylization.",
    )
    parser.add_argument(
        "--gen-backend",
        choices=["anthropic", "openrouter"],
        default=os.environ.get("FRAGBENCH_GEN_BACKEND", "openrouter"),
        help="LLM backend for generation-side rewriting (default: openrouter).",
    )
    parser.add_argument(
        "--gen-model",
        default=os.environ.get("FRAGBENCH_GEN_MODEL", DEFAULT_OPENROUTER_GENERATOR_MODEL),
        help="Model id for generation-side rewriting.",
    )
    parser.add_argument(
        "--gen-base-url",
        default=os.environ.get("OPENROUTER_BASE_URL", DEFAULT_OPENROUTER_BASE_URL),
        help="Base URL for OpenAI-compatible generation backends.",
    )
    parser.add_argument(
        "--claude-key",
        default=os.environ.get("ANTHROPIC_API_KEY"),
        help="Anthropic API key for generation-side rewriting.",
    )
    parser.add_argument(
        "--openrouter-key",
        default=os.environ.get("OPENROUTER_API_KEY"),
        help="OpenRouter API key for generation-side rewriting.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Write JSON to this file path instead of stdout.",
    )
    parser.add_argument(
        "--indent",
        type=int,
        default=2,
        help="JSON indentation spaces (default: 2).",
    )
    return parser.parse_args()


def load_seed(seed_file: str | Path) -> dict[str, Any]:
    path = Path(seed_file)
    return json.loads(path.read_text())


def build_generator(seed_data: dict[str, Any], seed_file: str | Path):
    campaign_id = str(seed_data["metadata"]["id"]).lower()
    if campaign_id not in VARIATION_REGISTRY:
        raise KeyError(
            f"No variation registered for metadata.id={seed_data['metadata']['id']!r} "
            f"(normalized key={campaign_id!r})"
        )
    return VARIATION_REGISTRY[campaign_id](str(seed_file)), campaign_id


def resolve_api_key(args: argparse.Namespace) -> str | None:
    if args.gen_backend == "anthropic":
        return args.claude_key
    return args.openrouter_key


def resolve_styles(args: argparse.Namespace) -> list[str]:
    styles = [s.strip() for s in (args.styles or "").split(",") if s.strip()]
    if not styles:
        styles = ["direct"]
    invalid = [s for s in styles if s not in STYLES]
    if invalid:
        raise ValueError(
            f"unknown styles: {', '.join(invalid)}. Available: {', '.join(STYLES)}"
        )
    return styles


def inspect_one_variation(
    *,
    seed_data: dict[str, Any],
    gen,
    seed_value: int,
    args: argparse.Namespace,
    styles: list[str],
) -> dict[str, Any]:
    api_key = resolve_api_key(args)
    stage_descriptions = [
        stage.get("description", f"Stage {idx}")
        for idx, stage in enumerate(seed_data.get("attack_stages", []))
    ]

    var = gen.make_variation(seed_value)
    raw_groups = (
        make_fragment_groups(
            var,
            api_key=api_key,
            backend=args.gen_backend,
            model=args.gen_model,
            base_url=args.gen_base_url,
        )
        if args.fragment
        else [[step] for step, _ in var]
    )

    fragments: list[dict[str, Any]] = []
    flat_fragment_index = 0

    for stage_index, group in enumerate(raw_groups):
        parent_prompt, parent_tactic = var[stage_index]
        stage_description = stage_descriptions[stage_index] if stage_index < len(stage_descriptions) else f"Stage {stage_index}"

        if not group:
            group = [parent_prompt]

        if args.stylize:
            generated_fragments = stylize_fragment_group(
                FragmentGroup(
                    parent_step=parent_prompt,
                    parent_tactic=str(parent_tactic),
                    sub_fragments=group,
                ),
                styles=styles,
                api_key=api_key,
                model=args.gen_model,
                backend=args.gen_backend,
                base_url=args.gen_base_url,
            )
            if args.legitimize:
                for generated_fragment in generated_fragments:
                    for variation in generated_fragment.variations:
                        variation.prompt = legitimize_fragment(
                            variation.prompt,
                            api_key=api_key,
                            model=args.gen_model,
                            backend=args.gen_backend,
                            base_url=args.gen_base_url,
                        )
            fragment_entries = [
                {
                    "fragment_index": flat_fragment_index + local_index,
                    "stage_index": stage_index,
                    "stage_description": stage_description,
                    "fragment_local_index": local_index,
                    "fragment_description": generated_fragment.description,
                    "parent_prompt": parent_prompt,
                    "parent_tactic": str(parent_tactic),
                    "variations": [
                        {
                            "style": variation.style,
                            "prompt": variation.prompt,
                        }
                        for variation in generated_fragment.variations
                    ],
                }
                for local_index, generated_fragment in enumerate(generated_fragments)
            ]
        else:
            fragment_entries = [
                {
                    "fragment_index": flat_fragment_index + local_index,
                    "stage_index": stage_index,
                    "stage_description": stage_description,
                    "fragment_local_index": local_index,
                    "fragment_description": fragment_text,
                    "parent_prompt": parent_prompt,
                    "parent_tactic": str(parent_tactic),
                    "variations": [
                        {
                            "style": "direct",
                            "prompt": (
                                legitimize_fragment(
                                    fragment_text,
                                    api_key=api_key,
                                    model=args.gen_model,
                                    backend=args.gen_backend,
                                    base_url=args.gen_base_url,
                                )
                                if args.legitimize
                                else fragment_text
                            ),
                        }
                    ],
                }
                for local_index, fragment_text in enumerate(group)
            ]

        fragments.extend(fragment_entries)
        flat_fragment_index += len(fragment_entries)

    return {
        "campaign_id": f"{seed_data['metadata']['id']}_{seed_value}",
        "campaign": seed_data["metadata"]["id"],
        "seed": seed_value,
        "total_stages": len(var),
        "total_fragments": len(fragments),
        "fragmentation_enabled": bool(args.fragment),
        "stylize_enabled": bool(args.stylize),
        "legitimize_enabled": bool(args.legitimize),
        "styles": styles if args.stylize else ["direct"],
        "fragments": fragments,
    }


def main() -> None:
    args = parse_args()
    seed_data = load_seed(args.seed_file)
    gen, _ = build_generator(seed_data, args.seed_file)
    styles = resolve_styles(args)

    base_seed = args.seed if args.seed is not None else random.randint(0, 2**31)
    samples = [
        inspect_one_variation(
            seed_data=seed_data,
            gen=gen,
            seed_value=base_seed + i,
            args=args,
            styles=styles,
        )
        for i in range(args.num_variations)
    ]

    payload: Any = samples[0] if len(samples) == 1 else samples
    rendered = json.dumps(payload, indent=args.indent) + "\n"

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(rendered)
    else:
        sys.stdout.write(rendered)


if __name__ == "__main__":
    main()
