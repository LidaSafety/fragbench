#!/usr/bin/env python3
"""Convert generated attack batch TOMLs into fragbench_samples-style JSON.

Mapping notes (deterministic):
- One TOML file => one sample object.
- One TOML stage/fragment/variation prompt => one output fragment entry.
- No true cover fragments exist in generated TOMLs, so all output fragments are
  attack fragments.
- time_offset_sec is synthetic and deterministic: 15-minute increments by
  flattened order.

This script expects the current generated TOML schema:
    stages -> fragments -> variations
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from datetime import datetime
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from harness import AttackMetadata, AttackSpec, Fragment, Stage, Variation, load_attack  # noqa: E402


GENERATED_FILE_RE = re.compile(r"^generated_(?P<campaign>.+)_(?P<seed>-?\d+)\.toml$")
TRAILING_SEED_RE = re.compile(r"^(?P<campaign>.+)_(?P<seed>-?\d+)$")

STOPWORDS = {
    "a",
    "an",
    "and",
    "as",
    "at",
    "for",
    "from",
    "in",
    "into",
    "of",
    "on",
    "or",
    "the",
    "to",
    "using",
    "with",
}

TACTIC_CAPABILITIES: dict[str, list[str]] = {
    "reconnaissance": ["recon", "net_out"],
    "resource_development": ["net_out"],
    "initial_access": ["net_out", "proc_exec"],
    "execution": ["proc_exec"],
    "persistence": ["proc_exec"],
    "privilege_escalation": ["proc_exec", "cred_access"],
    "defense_evasion": ["proc_exec"],
    "credential_access": ["cred_access", "file_read"],
    "discovery": ["recon", "proc_exec"],
    "lateral_movement": ["cred_access", "net_out", "proc_exec"],
    "collection": ["file_read"],
    "command_and_control": ["net_out", "proc_exec"],
    "exfiltration": ["file_read", "net_out", "crypto"],
    "impact": ["file_write", "crypto", "proc_exec"],
}

SOURCE_NAME_OVERRIDES = {
    "ANTHROPIC": "Anthropic",
    "GTIG": "Google Threat Intelligence Group",
    "SL": "SentinelLABS",
    "OPENAI": "OpenAI",
}

LLM_PRODUCT_PRIORITY = [
    "Claude Code",
    "v0",
    "Cursor",
    "Gemini",
    "GPT-4",
    "OpenAI",
    "Claude",
    "Lovable AI",
]


def normalize_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def parse_generated_filename(path: Path) -> tuple[str | None, int | None]:
    match = GENERATED_FILE_RE.match(path.name)
    if not match:
        return None, None
    return match.group("campaign"), int(match.group("seed"))


def parse_campaign_from_metadata_id(metadata_id: str) -> str:
    match = TRAILING_SEED_RE.match(metadata_id)
    if match:
        return match.group("campaign")
    return metadata_id


def parse_report_date(value: str) -> datetime | None:
    text = value.strip()
    if not text:
        return None

    for fmt in ("%Y-%m-%d", "%Y-%m", "%Y"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def derive_campaign_date(seed_metadata: dict[str, Any]) -> str:
    reports = seed_metadata.get("source_reports", [])
    dates = []
    for report in reports:
        report_date = parse_report_date(str(report.get("date", "")))
        if report_date is not None:
            dates.append(report_date)

    if not dates:
        return "Unknown"
    return min(dates).strftime("%b %Y")


def derive_campaign_source(seed_metadata: dict[str, Any]) -> str:
    reports = seed_metadata.get("source_reports", [])
    if not reports:
        return "Unknown"

    first = reports[0]
    source_id = str(first.get("id", "")).strip()
    if not source_id:
        return "Unknown"

    prefix = source_id.split("-", 1)[0].strip()
    if not prefix:
        return "Unknown"
    if prefix in SOURCE_NAME_OVERRIDES:
        return SOURCE_NAME_OVERRIDES[prefix]
    if len(prefix) <= 5:
        return prefix
    return prefix.title()


def text_mentions_v0(text: str) -> bool:
    if "v0 by vercel" in text or "vercel v0" in text:
        return True
    if not re.search(r"\bv0\b", text):
        return False
    return "vercel" in text or "using v0" in text or "use v0" in text


def score_llm_product_mentions(text: str, weight: float, scores: dict[str, float]) -> None:
    normalized = text.lower().strip()
    if not normalized:
        return

    has_claude_code = "claude_code" in normalized or "claude code" in normalized
    if has_claude_code:
        scores["Claude Code"] += weight

    if text_mentions_v0(normalized):
        scores["v0"] += weight
    if re.search(r"\bcursor\b", normalized):
        scores["Cursor"] += weight
    if re.search(r"\bgemini\b", normalized):
        scores["Gemini"] += weight
    if "gpt4" in normalized or "gpt-4" in normalized:
        scores["GPT-4"] += weight
    if "openai" in normalized or "chatgpt" in normalized:
        scores["OpenAI"] += weight
    if "lovable_ai" in normalized or "lovable ai" in normalized or "lovable.dev" in normalized:
        scores["Lovable AI"] += weight

    has_generic_claude = re.search(r"\bclaude\b", normalized) is not None or "anthropic" in normalized
    if has_generic_claude and not has_claude_code:
        scores["Claude"] += weight


def infer_llm_product(spec: AttackSpec) -> str:
    scores = {product: 0.0 for product in LLM_PRODUCT_PRIORITY}

    for stage in spec.stages:
        for fragment in stage.fragments:
            for variation in fragment.variations:
                score_llm_product_mentions(variation.prompt, weight=3.0, scores=scores)
            score_llm_product_mentions(fragment.description, weight=1.5, scores=scores)
        score_llm_product_mentions(stage.description, weight=0.5, scores=scores)

    score_llm_product_mentions(spec.metadata.description, weight=0.5, scores=scores)
    for tag in spec.metadata.tags:
        score_llm_product_mentions(str(tag), weight=0.25, scores=scores)

    best_product = max(
        LLM_PRODUCT_PRIORITY,
        key=lambda product: (scores[product], -LLM_PRODUCT_PRIORITY.index(product)),
    )
    if scores[best_product] <= 0:
        return "Unknown"
    return best_product


def make_phase_slug(description: str, phase_index: int) -> str:
    words = re.findall(r"[a-z0-9]+", description.lower())
    if not words:
        return f"phase_{phase_index}"

    filtered = [word for word in words if word not in STOPWORDS]
    tokens = (filtered or words)[:3]
    phase = "_".join(tokens)
    if phase[0].isdigit():
        return f"phase_{phase}"
    return phase


def infer_capabilities(stage: dict[str, Any] | None) -> list[str]:
    if stage is None:
        return []
    tactic = str(stage.get("mitre_tactic", "")).strip().lower()
    if not tactic:
        return []
    return TACTIC_CAPABILITIES.get(tactic, [])


def load_seed_index(seeds_dir: Path) -> dict[str, dict[str, Any]]:
    seed_index: dict[str, dict[str, Any]] = {}
    if not seeds_dir.exists() or not seeds_dir.is_dir():
        return seed_index

    for seed_path in sorted(seeds_dir.glob("*.json")):
        seed_data = json.loads(seed_path.read_text())
        metadata = seed_data.get("metadata", {})

        keys = {normalize_key(seed_path.stem)}
        metadata_id = str(metadata.get("id", "")).strip()
        if metadata_id:
            keys.add(normalize_key(metadata_id))

        for alias in metadata.get("aliases", []) or []:
            alias_text = str(alias).strip()
            if alias_text:
                keys.add(normalize_key(alias_text))

        for key in keys:
            seed_index[key] = seed_data

    return seed_index


def resolve_seed(seed_index: dict[str, dict[str, Any]], *keys: str) -> dict[str, Any] | None:
    for key in keys:
        normalized = normalize_key(key)
        if normalized in seed_index:
            return seed_index[normalized]
    return None


def toml_sort_key(path: Path) -> tuple[str, int, str]:
    campaign, seed = parse_generated_filename(path)
    if campaign is None or seed is None:
        return ("~", 2**31 - 1, path.name)
    return (campaign.lower(), seed, path.name)


def _is_escaped_quote(text: str, index: int) -> bool:
    backslashes = 0
    cursor = index - 1
    while cursor >= 0 and text[cursor] == "\\":
        backslashes += 1
        cursor -= 1
    return (backslashes % 2) == 1


def escape_unescaped_quotes(text: str) -> str:
    chars: list[str] = []
    for idx, char in enumerate(text):
        if char == '"' and not _is_escaped_quote(text, idx):
            chars.append("\\")
        chars.append(char)
    return "".join(chars)


def repair_string_line_quotes(line: str) -> str:
    quote_start = line.find('"')
    quote_end = line.rfind('"')
    if quote_start == -1 or quote_end <= quote_start:
        return line

    inner = line[quote_start + 1 : quote_end]
    fixed_inner = escape_unescaped_quotes(inner)
    if fixed_inner == inner:
        return line

    return f"{line[:quote_start + 1]}{fixed_inner}{line[quote_end:]}"


def repair_toml_string_quotes(raw_text: str) -> str:
    repaired_lines = []
    for line in raw_text.splitlines():
        stripped = line.strip()
        if "=" not in stripped or stripped.startswith("#") or stripped.count('"') < 2:
            repaired_lines.append(line)
            continue

        _, value_part = stripped.split("=", 1)
        value = value_part.strip()
        if value.startswith('"') and value.endswith('"'):
            repaired_lines.append(repair_string_line_quotes(line))
        else:
            repaired_lines.append(line)

    return "\n".join(repaired_lines) + ("\n" if raw_text.endswith("\n") else "")


def build_attack_spec_from_toml_data(data: dict[str, Any]) -> AttackSpec:
    meta = data["metadata"]
    metadata = AttackMetadata(
        id=meta["id"],
        technique=meta["technique"],
        technique_name=meta["technique_name"],
        description=meta["description"],
        tags=meta.get("tags", []),
    )

    stages: list[Stage] = []
    for stage_data in data.get("stages", []):
        stage_index = stage_data["index"]
        stage_description = stage_data["description"]
        fragments = [
            Fragment(
                index=frag_data["index"],
                description=frag_data["description"],
                stage_index=stage_index,
                stage_description=stage_description,
                variations=[
                    Variation(style=variation["style"], prompt=variation["prompt"])
                    for variation in frag_data.get("variations", [])
                ],
            )
            for frag_data in stage_data.get("fragments", [])
        ]
        stages.append(Stage(index=stage_index, description=stage_description, fragments=fragments))

    return AttackSpec(metadata=metadata, stages=stages)


def load_attack_with_repair(path: Path) -> AttackSpec:
    try:
        return load_attack(path)
    except tomllib.TOMLDecodeError:
        raw_text = path.read_text()
        repaired_text = repair_toml_string_quotes(raw_text)
        data = tomllib.loads(repaired_text)
        return build_attack_spec_from_toml_data(data)


def build_sample(
    toml_path: Path,
    user_id: int,
    seed_index: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    spec = load_attack_with_repair(toml_path)
    filename_campaign, _ = parse_generated_filename(toml_path)
    metadata_campaign = parse_campaign_from_metadata_id(spec.metadata.id)
    seed_data = resolve_seed(seed_index, metadata_campaign, filename_campaign or "")

    seed_metadata = seed_data.get("metadata", {}) if seed_data else {}
    seed_stages = seed_data.get("attack_stages", []) if seed_data else []
    stage_by_index = {
        int(stage.get("index")): stage
        for stage in seed_stages
        if isinstance(stage, dict) and isinstance(stage.get("index"), int)
    }

    aliases = seed_metadata.get("aliases") or []
    campaign_name = str(aliases[0]) if aliases else str(seed_metadata.get("id") or metadata_campaign)
    campaign_source = derive_campaign_source(seed_metadata)
    campaign_date = derive_campaign_date(seed_metadata)
    description = str(seed_metadata.get("description") or spec.metadata.description)
    llm_product = infer_llm_product(spec)

    sorted_stages = sorted(spec.stages, key=lambda stage: stage.index)

    phase_names_by_index: dict[int, str] = {}
    used_phase_names: dict[str, int] = {}
    for stage in sorted_stages:
        phase_index = int(stage.index)
        if phase_index in phase_names_by_index:
            continue

        seed_stage = stage_by_index.get(phase_index)
        phase_description = str(seed_stage.get("description")) if seed_stage else stage.description
        base_phase_name = make_phase_slug(phase_description, phase_index)
        seen_count = used_phase_names.get(base_phase_name, 0)
        used_phase_names[base_phase_name] = seen_count + 1
        phase_name = base_phase_name if seen_count == 0 else f"{base_phase_name}_{seen_count + 1}"
        phase_names_by_index[phase_index] = phase_name

    output_fragments: list[dict[str, Any]] = []
    fragment_counter = 0
    for stage in sorted_stages:
        phase_index = int(stage.index)
        phase_name = phase_names_by_index.get(phase_index, f"phase_{phase_index}")
        seed_stage = stage_by_index.get(phase_index)
        capabilities = infer_capabilities(seed_stage)

        for fragment in sorted(stage.fragments, key=lambda item: item.index):
            for variation_index, variation in enumerate(fragment.variations):
                output_fragments.append(
                    {
                        "fragment_id": (
                            f"{user_id}_phase{phase_index}_fragment{fragment.index}_var{variation_index}"
                        ),
                        "prompt": variation.prompt,
                        "phase": phase_name,
                        "phase_index": phase_index,
                        "capabilities_activated": capabilities,
                        "is_cover": False,
                        "time_offset_sec": float(fragment_counter * 900),
                    }
                )
                fragment_counter += 1

    phases_in_order = []
    seen_phases = set()
    for fragment in output_fragments:
        phase = fragment["phase"]
        if phase in seen_phases:
            continue
        seen_phases.add(phase)
        phases_in_order.append(phase)

    total_fragments = len(output_fragments)
    num_cover_fragments = 0
    num_attack_fragments = total_fragments
    max_offset = max((fragment["time_offset_sec"] for fragment in output_fragments), default=0.0)
    duration_hours = round(max_offset / 3600, 2)

    return {
        "user_id": user_id,
        "campaign": campaign_name,
        "campaign_source": campaign_source,
        "campaign_date": campaign_date,
        "llm_product": llm_product,
        "campaign_description": description,
        "duration_hours": duration_hours,
        "num_total_fragments": total_fragments,
        "num_attack_fragments": num_attack_fragments,
        "num_cover_fragments": num_cover_fragments,
        "phases_in_order": phases_in_order,
        "fragments": output_fragments,
    }


def convert_batch_to_samples(
    input_batch_dir: Path,
    output_json_path: Path,
    seeds_dir: Path,
    indent: int,
) -> None:
    if not input_batch_dir.exists() or not input_batch_dir.is_dir():
        raise ValueError(f"Input batch directory does not exist or is not a directory: {input_batch_dir}")

    toml_files = sorted(input_batch_dir.glob("*.toml"), key=toml_sort_key)
    if not toml_files:
        raise ValueError(f"No TOML files found in batch directory: {input_batch_dir}")

    seed_index = load_seed_index(seeds_dir)
    samples = [
        build_sample(toml_path=toml_path, user_id=user_id, seed_index=seed_index)
        for user_id, toml_path in enumerate(toml_files)
    ]

    output_json_path.parent.mkdir(parents=True, exist_ok=True)
    output_json_path.write_text(json.dumps(samples, indent=indent) + "\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Convert a generated attack batch directory into a fragbench_samples-style JSON array."
    )
    parser.add_argument(
        "input_batch_dir",
        type=Path,
        help="Input directory containing generated_*.toml files.",
    )
    parser.add_argument(
        "output_json",
        type=Path,
        help="Output JSON file path.",
    )
    parser.add_argument(
        "--seeds-dir",
        type=Path,
        default=REPO_ROOT / "seeds",
        help="Directory containing campaign seed JSON files (default: <repo>/seeds).",
    )
    parser.add_argument(
        "--indent",
        type=int,
        default=2,
        help="JSON indentation spaces (default: 2).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    convert_batch_to_samples(
        input_batch_dir=args.input_batch_dir,
        output_json_path=args.output_json,
        seeds_dir=args.seeds_dir,
        indent=args.indent,
    )


if __name__ == "__main__":
    main()
