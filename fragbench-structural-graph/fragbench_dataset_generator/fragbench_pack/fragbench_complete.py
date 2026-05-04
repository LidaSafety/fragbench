"""
FragBench Complete Dataset Generator
======================================
Merges fragbench_gen.py + fragbench_ext.py into one dataset:
  - 35 campaigns (INC-001 to INC-035)
  - 5 multi-turn chains (CHAIN-001 to CHAIN-005)
  - 7 benign archetypes
  - Configurable mix of malicious/benign/chain samples

Usage:
    python fragbench_complete.py --num_samples 1000 --output dataset.json
    python fragbench_complete.py --num_samples 100000 --output dataset.jsonl.gz --format jsonl_gz
    python fragbench_complete.py --num_samples 1000 --benign_ratio 0.5 --include_chains --output full.json
"""

import json, gzip, argparse, time, numpy as np
from collections import Counter

# Import from base and extension
from fragbench_gen import CAMPAIGNS as BASE_CAMPAIGNS, COVER_PROMPTS, KILL_CHAINS
from fragbench_ext import (
    EXTRA_CAMPAIGNS, CHAINS, BENIGN_ARCHETYPES, generate_benign_sample
)

# Merge all campaigns
ALL_CAMPAIGNS = {}
ALL_CAMPAIGNS.update(BASE_CAMPAIGNS)
ALL_CAMPAIGNS.update(EXTRA_CAMPAIGNS)


def generate_sample(uid, campaign_id, rng):
    """Generate one malicious user sample from merged campaign registry."""
    camp = ALL_CAMPAIGNS[campaign_id]
    fragments, all_mitre, task_sums = [], set(), []
    for ti, task in enumerate(camp["tasks"]):
        lo, hi = task["frags"]
        nf = int(rng.integers(lo, hi + 1))
        ps = len(task["prompts"])
        chosen = rng.choice(ps, size=min(nf, ps), replace=False)
        all_mitre.add(task["mitre"])
        task_sums.append({"task_index": ti, "task_name": task["name"],
            "mitre_tactic": task["mitre"], "mitre_id": task["mitre_id"],
            "num_fragments": len(chosen)})
        for fi, pidx in enumerate(chosen):
            fragments.append({"id": f"{uid}_t{ti}_f{fi}", "prompt": task["prompts"][pidx],
                "task_index": ti, "task_name": task["name"], "mitre_tactic": task["mitre"],
                "mitre_id": task["mitre_id"], "is_cover": False})
    na = len(fragments)
    nc = int(rng.integers(max(3, na), max(5, na * 2)))
    for ci, cx in enumerate(rng.choice(len(COVER_PROMPTS), size=nc, replace=True)):
        fragments.append({"id": f"{uid}_cover_{ci}", "prompt": COVER_PROMPTS[cx],
            "task_index": -1, "task_name": "cover", "mitre_tactic": None,
            "mitre_id": None, "is_cover": True})
    rng.shuffle(fragments)
    return {"user_id": uid, "campaign_id": campaign_id,
        "campaign_full_name": camp["full_name"], "campaign_source": camp["source"],
        "campaign_date": camp.get("date", ""), "llm_product": camp.get("llm", ""),
        "attribution": camp.get("attribution", ""),
        "campaign_description": camp.get("description", ""),
        "num_tasks": len(camp["tasks"]), "num_fragments": len(fragments),
        "num_attack_fragments": na, "num_cover_fragments": len(fragments) - na,
        "mitre_tactics_used": sorted(all_mitre), "tasks": task_sums, "fragments": fragments}


def generate_chain_sample(chain_id, chain_def, uid):
    """Generate a multi-turn chain sample."""
    return {
        "user_id": uid,
        "label": "chain",
        "campaign_id": chain_id,
        "campaign_full_name": chain_def["name"],
        "campaign_source": f"Chain (source: {chain_def['source_incident']})",
        "attack_type": chain_def["attack_type"],
        "kill_chain_phases": chain_def["kill_chain_phases"],
        "num_fragments": len(chain_def["steps"]),
        "num_attack_fragments": len(chain_def["steps"]),
        "num_cover_fragments": 0,
        "mitre_tactics_used": list(set(s["mitre_id"] for s in chain_def["steps"])),
        "tasks": [],
        "fragments": [
            {
                "id": f"chain_{uid}_step{s['step']}",
                "prompt": s["prompt"],
                "step": s["step"],
                "phase": s["phase"],
                "expected_behavior": s["expected_behavior"],
                "mitre_id": s["mitre_id"],
                "is_cover": False,
            }
            for s in chain_def["steps"]
        ],
    }


def generate_dataset(num_samples, output_path, fmt="json", seed=42,
                     benign_ratio=0.0, include_chains=False):
    rng = np.random.default_rng(seed)

    n_chains = len(CHAINS) if include_chains else 0
    n_benign = int(num_samples * benign_ratio)
    n_malicious = num_samples - n_benign - n_chains

    camp_ids = list(ALL_CAMPAIGNS.keys())
    mal_assignments = rng.choice(camp_ids, size=n_malicious)

    arch_names = list(BENIGN_ARCHETYPES.keys())
    ben_assignments = rng.choice(arch_names, size=n_benign) if n_benign > 0 else []

    total = n_malicious + n_benign + n_chains
    print(f"Generating {total:,} samples:")
    print(f"  Malicious: {n_malicious:,} ({len(camp_ids)} campaigns)")
    print(f"  Benign:    {n_benign:,} ({len(arch_names)} archetypes)")
    print(f"  Chains:    {n_chains}")
    t0 = time.perf_counter()

    def all_samples():
        uid = 0
        # Malicious
        for i in range(n_malicious):
            if uid % 10_000 == 0 and uid > 0:
                print(f"  {uid:>8,} / {total:,}")
            sample = generate_sample(uid, str(mal_assignments[i]), rng)
            sample["label"] = "malicious"
            sample["category"] = ALL_CAMPAIGNS[str(mal_assignments[i])].get("category", "confirmed")
            yield sample
            uid += 1
        # Benign
        for i in range(n_benign):
            if uid % 10_000 == 0 and uid > 0:
                print(f"  {uid:>8,} / {total:,}")
            yield generate_benign_sample(uid, str(ben_assignments[i]), rng, COVER_PROMPTS)
            uid += 1
        # Chains
        if include_chains:
            for chain_id, chain_def in CHAINS.items():
                yield generate_chain_sample(chain_id, chain_def, uid)
                uid += 1

    if fmt == "json":
        samples = list(all_samples())
        with open(output_path, "w") as f:
            json.dump(samples, f, indent=2)
    elif fmt == "jsonl":
        with open(output_path, "w") as f:
            for s in all_samples():
                f.write(json.dumps(s) + "\n")
    elif fmt == "jsonl_gz":
        with gzip.open(output_path, "wt", compresslevel=6) as f:
            for s in all_samples():
                f.write(json.dumps(s) + "\n")

    import os
    elapsed = time.perf_counter() - t0
    print(f"\nDone in {elapsed:.1f}s — {os.path.getsize(output_path)/1e6:.1f} MB")

    # Stats
    print(f"\nCampaign distribution (malicious):")
    counts = Counter(mal_assignments)
    for cid in sorted(camp_ids):
        c = ALL_CAMPAIGNS[cid]
        cat = c.get("category", "confirmed")
        tag = "✓" if cat == "confirmed" else "~"
        print(f"  {tag} {cid} ({c['full_name']:<35s})  n={counts.get(cid,0):>5,}  "
              f"tasks={len(c['tasks'])}  src={c['source']}")

    if n_benign > 0:
        print(f"\nBenign archetype distribution:")
        bcounts = Counter(ben_assignments)
        for an in arch_names:
            print(f"  {an:<20s}  n={bcounts.get(an,0):>5,}")

    if include_chains:
        print(f"\nMulti-turn chains:")
        for cid, cdef in CHAINS.items():
            print(f"  {cid}: {cdef['name']} ({len(cdef['steps'])} steps, "
                  f"source: {cdef['source_incident']})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FragBench complete dataset generator")
    parser.add_argument("--num_samples", type=int, default=100)
    parser.add_argument("--output", type=str, default="fragbench_complete.json")
    parser.add_argument("--format", type=str, default="json", choices=["json", "jsonl", "jsonl_gz"])
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--benign_ratio", type=float, default=0.0,
                        help="Fraction of samples that are benign (0.0 to 1.0)")
    parser.add_argument("--include_chains", action="store_true",
                        help="Include the 5 multi-turn attack chains")
    args = parser.parse_args()

    generate_dataset(args.num_samples, args.output, args.format, args.seed,
                     args.benign_ratio, args.include_chains)
