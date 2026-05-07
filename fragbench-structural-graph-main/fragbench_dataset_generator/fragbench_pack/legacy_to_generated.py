"""
Legacy → generated-format adapter
=================================
Convert one of the per-campaign files under malicious_chains_size100_pass_per_campaign/
(legacy `samples[*].fragments[*]` shape with `original` / `rewritten` /
`original_question_form` / `rewritten_question_form`) into the dataset shape
that fragbench_generated_rl.py consumes (`variations[*].fragments[*].variations[*]`
with `style` / `prompt`).

Each legacy `sample` becomes one outer variation. Each legacy fragment becomes
one inner-fragment whose `variations` list carries up to four entries — one
per available prompt field — with these styles:

    original          ← fragment["original"]
    rewritten         ← fragment["rewritten"]
    original_question ← fragment["original_question_form"]
    rewritten_question← fragment["rewritten_question_form"]

After conversion, judge with whichever model you want (results land in each
inner variation's `judge_verdict`); use a per-model `--output` path to keep
runs from clobbering each other:

    python legacy_to_generated.py \\
        --input  malicious_chains_size100_pass_per_campaign/INC-006_PROMPTSTEAL_APT28.json \\
        --output /tmp/INC-006_generated.json

    python fragbench_generated_rl.py --mode judge --use_api \\
        --input  /tmp/INC-006_generated.json \\
        --output /tmp/INC-006_judged_llamaguard.json \\
        --variation-style rewritten        # pick which field to judge
"""

import argparse
import json
from pathlib import Path

# Legacy field → style label fed to fragbench_generated_rl's --variation-style.
PROMPT_FIELDS = [
    ("original", "original"),
    ("rewritten", "rewritten"),
    ("original_question_form", "original_question"),
    ("rewritten_question_form", "rewritten_question"),
]

# Legacy fragment keys passed through verbatim onto the new fragment dict
# (everything that isn't a prompt field or one of the renamed ones).
PASSTHROUGH_FRAG_KEYS = [
    "id", "is_attack", "is_cover", "task", "mitre", "mitre_id",
    "judge_verdict", "rl_round", "rl_strategy",
]


def convert(legacy):
    if "samples" not in legacy:
        raise SystemExit(
            "Input doesn't look like the legacy format: missing 'samples' key.")

    camp_id = legacy.get("campaign_id", "")
    camp_name = legacy.get("campaign_name", "")
    camp_full_prompt = legacy.get("full_prompt", "")
    category = legacy.get("category", "")

    variations = []
    for sample in legacy["samples"]:
        sample_full_prompt = sample.get("full_prompt", camp_full_prompt)
        sample_camp_id = sample.get("campaign_id", camp_id)

        fragments = []
        for frag in sample.get("fragments", []):
            inner_vars = []
            for legacy_key, style in PROMPT_FIELDS:
                prompt = frag.get(legacy_key)
                if not prompt:
                    continue
                inner_vars.append({"style": style, "prompt": prompt})
            if not inner_vars:
                continue

            new_frag = {
                "fragment_index": frag.get("task_idx"),
                "parent_prompt": sample_full_prompt,
                "parent_tactic": frag.get("mitre", ""),
                "variations": inner_vars,
                "role": ("attack" if frag.get("is_attack")
                         else "cover" if frag.get("is_cover") else None),
            }
            for k in PASSTHROUGH_FRAG_KEYS:
                if k in frag:
                    new_frag[k] = frag[k]
            fragments.append(new_frag)

        variations.append({
            "campaign_id": sample_camp_id,
            "user_id": sample.get("user_id"),
            "metadata": {
                "id": sample_camp_id,
                "technique_name": camp_name,
                "description": sample_full_prompt,
                "category": category,
                "source": legacy.get("source", ""),
            },
            "total_fragments": len(fragments),
            "fragments": fragments,
            "legacy_pass_rate": sample.get("pass_rate"),
        })

    return {
        "campaign": camp_id or camp_name,
        "campaign_name": camp_name,
        "source": legacy.get("source", ""),
        "category": category,
        "full_prompt": camp_full_prompt,
        "num_variations": len(variations),
        "variations": variations,
        "_converted_from_legacy": True,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--input", required=True,
                   help="Legacy per-campaign JSON file")
    p.add_argument("--output", required=True,
                   help="Where to write the generated-format JSON")
    args = p.parse_args()

    legacy = json.loads(Path(args.input).read_text())
    out = convert(legacy)
    Path(args.output).write_text(json.dumps(out, indent=2))

    n_inner = sum(len(f["variations"])
                  for v in out["variations"] for f in v["fragments"])
    print(f"Converted {args.input} → {args.output}")
    print(f"  variations (samples):  {len(out['variations'])}")
    print(f"  fragments (total):     {sum(len(v['fragments']) for v in out['variations'])}")
    print(f"  inner variations:      {n_inner}")


if __name__ == "__main__":
    main()
