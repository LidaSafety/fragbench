#!/usr/bin/env python3
"""
FragBench — Unified Dataset Generator
========================================

Single CLI for all FragBench operations. Inherits from the module hierarchy:

    fragbench_gen.py       ← 25 confirmed campaigns (INC-001 to INC-027)
    fragbench_ext.py       ← INC-018/019, INC-028-035, CHAIN-001-005, benign archetypes
    fragbench_hard.py      ← shared-pool hard mode (F1≈0.55)
    fragbench_scalable.py  ← prompt variation + scaling to 1B
    fragbench_modes.py     ← Mode 1 (hard, 100% ASR) + Mode 2 (RL, 43%→100%)
    fragbench_rl.py        ← REINFORCE policy network (TF-IDF state)
    fragbench_llm_rl.py    ← LLM-generative RL (strategy memory + Opus 4.6 judge)
    fragbench_judge_rl.py  ← Opus 4.6 judge + simulated judge

Commands:
    # ── Generate datasets ──
    fragbench generate --campaigns all --size 1000 --output dataset.json
    fragbench generate --campaigns confirmed --size 100000 --format jsonl_gz
    fragbench generate --campaigns INC-001,INC-014,INC-027 --size 500

    # ── Mode 1: Pre-hardened (100% ASR) ──
    fragbench hard --size 1000 --output hard.json

    # ── Mode 2: RL trajectory (43%→100%) ──
    fragbench rl --size 1000 --rounds 10 --output_dir checkpoints/
    fragbench rl --size 1000 --rounds 10 --method policy   # REINFORCE
    fragbench rl --size 1000 --rounds 10 --method llm      # LLM-generative

    # ── Evaluate ──
    fragbench eval --input dataset.json               # F1, per-campaign P/R/F1
    fragbench eval --input dataset.json --classifier gbt

    # ── Judge ──
    fragbench judge --input dataset.json --output judged.json
    fragbench judge --input dataset.json --use_api    # real Opus 4.6

    # ── Scale info ──
    fragbench scale --sizes 100,100K,1M,100M,1B

    # ── Visualize ──
    fragbench viz --output dashboard_data.json
"""

import sys
import json
import os
import argparse
import time
import copy
import numpy as np
from collections import Counter, defaultdict


def load_all_campaigns():
    """Load and merge all 35 campaigns."""
    from fragbench_gen import CAMPAIGNS as BASE
    from fragbench_ext import EXTRA_CAMPAIGNS as EXT
    all_c = {}
    all_c.update(BASE)
    all_c.update(EXT)
    return all_c


def load_chains():
    from fragbench_ext import CHAINS
    return CHAINS


def load_benign_archetypes():
    from fragbench_ext import BENIGN_ARCHETYPES
    return BENIGN_ARCHETYPES


def load_cover_prompts():
    from fragbench_gen import COVER_PROMPTS
    return COVER_PROMPTS


def filter_campaigns(all_campaigns, selector):
    """Filter campaigns by selector string."""
    if selector == "all":
        return all_campaigns
    elif selector == "confirmed":
        return {k: v for k, v in all_campaigns.items()
                if v.get("category", "confirmed") == "confirmed"}
    elif selector == "hypothetical":
        return {k: v for k, v in all_campaigns.items()
                if v.get("category", "confirmed") == "hypothetical"}
    else:
        # Comma-separated list of INC-XXX
        ids = [s.strip() for s in selector.split(",")]
        return {k: v for k, v in all_campaigns.items() if k in ids}


# ═══════════════════════════════════════════════════════════════════════════
# COMMAND: generate
# ═══════════════════════════════════════════════════════════════════════════

def cmd_generate(args):
    """Generate dataset with selected campaigns. --size = samples per campaign."""
    all_c = load_all_campaigns()
    campaigns = filter_campaigns(all_c, args.campaigns)
    cover = load_cover_prompts()

    camp_ids = sorted(campaigns.keys())
    n_camps = len(camp_ids)
    per_camp = args.size  # exactly this many per campaign
    # half malicious, half benign per campaign
    mal_per = per_camp // 2
    ben_per = per_camp - mal_per
    total = per_camp * n_camps

    print(f"GENERATE: {n_camps} campaigns × {per_camp} samples/campaign = {total:,} total")
    print(f"  Per campaign: {mal_per} malicious + {ben_per} benign")
    print(f"  Selector: {args.campaigns}")

    from fragbench_scalable import generate_one

    rng = np.random.default_rng(args.seed)
    t0 = time.perf_counter()

    # Generate all samples, split into two lists, grouped by campaign
    mal_samples = {}  # campaign_id → [samples]
    ben_samples = {}
    uid = 0
    for cid in camp_ids:
        mal_samples[cid] = []
        ben_samples[cid] = []
        for _ in range(mal_per):
            mal_samples[cid].append(generate_one(uid, cid, True, rng))
            uid += 1
        for _ in range(ben_per):
            ben_samples[cid].append(generate_one(uid, cid, False, rng))
            uid += 1

    # Derive output paths
    base = args.output
    if base.endswith(".json"):
        base = base[:-5]
    elif base.endswith(".jsonl"):
        base = base[:-6]
    elif base.endswith(".jsonl.gz"):
        base = base[:-9]

    ext = "." + args.format.replace("_", ".")

    mal_path = base + "_malicious" + ext
    ben_path = base + "_benign" + ext

    # Write grouped output: {campaign_id: [samples]}
    mal_flat = []
    ben_flat = []
    for cid in camp_ids:
        mal_flat.extend(mal_samples[cid])
        ben_flat.extend(ben_samples[cid])

    mal_grouped = {cid: mal_samples[cid] for cid in camp_ids}
    ben_grouped = {cid: ben_samples[cid] for cid in camp_ids}

    with open(mal_path, "w") as f:
        json.dump(mal_grouped, f, indent=2 if total <= 5000 else None)
    with open(ben_path, "w") as f:
        json.dump(ben_grouped, f, indent=2 if total <= 5000 else None)

    mal_size = os.path.getsize(mal_path)
    ben_size = os.path.getsize(ben_path)

    print(f"  Malicious: {len(mal_flat):,} samples → {mal_path} ({mal_size/1e6:.1f} MB)")
    print(f"  Benign:    {len(ben_flat):,} samples → {ben_path} ({ben_size/1e6:.1f} MB)")
    print(f"  Structure: {{campaign_id: [samples]}}")

    # Per-campaign summary
    print(f"\n  {'Campaign':<14s} {'Mal':>4s} {'Ben':>4s}")
    print(f"  {'-'*24}")
    for cid in camp_ids:
        print(f"  {cid:<14s} {len(mal_samples[cid]):>4d} {len(ben_samples[cid]):>4d}")
    print(f"  {'-'*24}")
    print(f"  {'TOTAL':<14s} {len(mal_flat):>4d} {len(ben_flat):>4d}")
    print(f"  Done: {time.perf_counter()-t0:.1f}s")


# ═══════════════════════════════════════════════════════════════════════════
# COMMAND: hard
# ═══════════════════════════════════════════════════════════════════════════

def cmd_hard(args):
    """Mode 1: Pre-hardened 100% ASR dataset. --size = samples per campaign."""
    from fragbench_modes import generate_hard, compute_asr
    all_c = load_all_campaigns()
    n_camps = len(all_c)
    total = args.size * n_camps
    print(f"  --size {args.size} × {n_camps} campaigns = {total:,} total")

    samples = generate_hard(total, "_tmp_hard.json", args.seed)

    # Group by campaign
    mal_grouped = {}
    ben_grouped = {}
    for s in samples:
        cid = s.get("campaign_id") or "unknown"
        if s.get("label") == "malicious":
            mal_grouped.setdefault(cid, []).append(s)
        else:
            ben_grouped.setdefault(cid, []).append(s)

    base = args.output
    if base.endswith(".json"):
        base = base[:-5]

    mal_path = base + "_malicious.json"
    ben_path = base + "_benign.json"

    with open(mal_path, "w") as f:
        json.dump(mal_grouped, f, indent=2 if total <= 5000 else None)
    with open(ben_path, "w") as f:
        json.dump(ben_grouped, f, indent=2 if total <= 5000 else None)

    if os.path.exists("_tmp_hard.json"):
        os.remove("_tmp_hard.json")

    # ASR only for malicious
    mal_flat = [s for ss in mal_grouped.values() for s in ss]
    ben_flat = [s for ss in ben_grouped.values() for s in ss]
    asr, passed, total_atk, per_camp = compute_asr(mal_flat)

    print(f"\n  Malicious: {len(mal_flat):,} samples → {mal_path}")
    print(f"  Benign:    {len(ben_flat):,} samples → {ben_path}")
    print(f"  Structure: {{campaign_id: [samples]}}")
    print(f"  ASR (malicious only): {asr:.4f} ({passed}/{total_atk})")

    # Per-campaign ASR
    print(f"\n  {'Campaign':<14s} {'#Mal':>5s} {'#Ben':>5s} {'ASR':>7s}")
    print(f"  {'-'*33}")
    for cid in sorted(mal_grouped.keys()):
        camp_asr = per_camp.get(cid, 0)
        n_mal = len(mal_grouped.get(cid, []))
        n_ben = len(ben_grouped.get(cid, []))
        print(f"  {cid:<14s} {n_mal:>5d} {n_ben:>5d} {camp_asr:>7.4f}")


# ═══════════════════════════════════════════════════════════════════════════
# COMMAND: rl
# ═══════════════════════════════════════════════════════════════════════════

def cmd_rl(args):
    """Mode 2: RL trajectory. --size = samples per campaign."""
    all_c = load_all_campaigns()
    n_camps = len(all_c)
    total = args.size * n_camps
    mal_per = args.size // 2
    ben_per = args.size - mal_per
    print(f"  --size {args.size} × {n_camps} campaigns = {total:,} total")
    print(f"  Per campaign: {mal_per} malicious + {ben_per} benign")

    if args.method == "policy":
        from fragbench_modes import generate_rl
        generate_rl(total, args.output_dir, args.rounds, args.seed)
    elif args.method == "llm":
        from fragbench_modes import generate_sample, compute_asr, CAMP_IDS
        from fragbench_llm_rl import run_llm_rl

        rng = np.random.default_rng(args.seed)
        samples = []
        uid = 0
        for cid in CAMP_IDS:
            for _ in range(mal_per):
                samples.append(generate_sample(uid, cid, True, rng, mode="raw"))
                uid += 1
            for _ in range(ben_per):
                samples.append(generate_sample(uid, cid, False, rng, mode="raw"))
                uid += 1

        os.makedirs(args.output_dir, exist_ok=True)
        simulate = not args.use_api
        optimized, trajectory, memory = run_llm_rl(
            samples, args.rounds, simulate, n_variants=3,
            bootstrap_db_path=getattr(args, "bootstrap_db", None))

        out_path = os.path.join(args.output_dir, f"llm_rl_size{args.size}_final.json")
        with open(out_path, "w") as f:
            json.dump(optimized, f)
        traj_path = os.path.join(args.output_dir, f"llm_rl_size{args.size}_trajectory.json")
        with open(traj_path, "w") as f:
            json.dump(trajectory, f, indent=2)

        # Save the rewrite policies that produced PASS verdicts so they can
        # be reused (transferred to bigger runs, audited, or re-applied
        # without re-querying the rewriter LLM).
        policy_path = os.path.join(args.output_dir, f"llm_rl_size{args.size}_policies.json")
        # Tally how many times each strategy_id produced a PASS.
        from collections import Counter
        strategy_pass_counts = Counter(s.get("strategy_id") for s in memory.successes)
        policies = {
            "successful_rewrites": memory.successes,
            "strategy_pass_counts": dict(strategy_pass_counts),
            "strategies": [
                {
                    "id": s.get("id"),
                    "description": s.get("description"),
                    "success_count": s.get("success_count", 0),
                    "fail_count": s.get("fail_count", 0),
                    "examples": s.get("examples", [])[:5],
                }
                for s in memory.strategies
            ],
            "discovered_strategies": memory.discovered,
        }
        with open(policy_path, "w") as f:
            json.dump(policies, f, indent=2, default=str)

        # Append every successful rewrite to a cross-run JSONL database so
        # subsequent RL runs can bootstrap from it via --bootstrap_db.
        # One JSON record per line — append-only, deduplicated on the
        # full (original, rewritten) PAIR. Multiple distinct rewrites of
        # the same original ARE allowed (they're useful — different
        # disguises for the same target). Identical pairs are skipped.
        db_path = os.path.join(args.output_dir, "policies_db.jsonl")
        existing_pairs = set()
        if os.path.exists(db_path):
            with open(db_path) as f:
                for line in f:
                    try:
                        r = json.loads(line)
                        existing_pairs.add((r.get("original"), r.get("rewritten")))
                    except Exception:
                        pass
        appended = 0
        with open(db_path, "a") as f:
            for s in memory.successes:
                key = (s.get("original"), s.get("rewritten"))
                if key in existing_pairs:
                    continue
                existing_pairs.add(key)
                rec = {
                    "original": s.get("original"),
                    "rewritten": s.get("rewritten"),
                    "strategy": s.get("strategy"),
                    "prompt_type": s.get("prompt_type"),
                    "size": args.size,
                    "rounds": args.rounds,
                }
                f.write(json.dumps(rec) + "\n")
                appended += 1
        print(f"Saved: {out_path}, {traj_path}, {policy_path}")
        print(f"Appended {appended} new bypass policies to {db_path}")
    else:
        from fragbench_modes import generate_sample, compute_asr, CAMP_IDS
        from fragbench_modes import rl_harden_round

        rng = np.random.default_rng(args.seed)
        samples = []
        uid = 0
        for cid in CAMP_IDS:
            for _ in range(mal_per):
                samples.append(generate_sample(uid, cid, True, rng, mode="raw"))
                uid += 1
            for _ in range(ben_per):
                samples.append(generate_sample(uid, cid, False, rng, mode="raw"))
                uid += 1

        os.makedirs(args.output_dir, exist_ok=True)
        current = samples
        for r in range(args.rounds):
            current, improved = rl_harden_round(current, r, rng)
            asr, passed, total_atk, _ = compute_asr(current)
            print(f"  Round {r+1}: ASR={asr:.4f} improved={improved}")
        out_path = os.path.join(args.output_dir, "rules_final.json")
        with open(out_path, "w") as f:
            json.dump(current, f)


# ═══════════════════════════════════════════════════════════════════════════
# COMMAND: eval
# ═══════════════════════════════════════════════════════════════════════════

def cmd_eval(args):
    """Evaluate dataset with TF-IDF + classifier, per-campaign breakdown."""
    with open(args.input) as f:
        if args.input.endswith(".jsonl"):
            samples = [json.loads(l) for l in f]
        else:
            samples = json.load(f)

    # Build docs and labels
    docs, labels, camp_labels = [], [], []
    for s in samples:
        doc = " ".join(f.get("prompt", "") for f in s.get("fragments", []))
        docs.append(doc)
        labels.append(1 if s.get("label") == "malicious" else 0)
        camp_labels.append(s.get("campaign_id") or s.get("campaign_name") or "benign")

    y = np.array(labels)
    camps = np.array(camp_labels)

    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.model_selection import train_test_split
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.metrics import classification_report, roc_auc_score

    tfidf = TfidfVectorizer(max_features=500, ngram_range=(1, 2), stop_words="english")
    X = tfidf.fit_transform(docs).toarray().astype(np.float32)

    all_idx = np.arange(len(docs))

    # Stratified split
    X_tr, X_te, y_tr, y_te, idx_tr, idx_te = train_test_split(
        X, y, all_idx, test_size=0.2, random_state=42, stratify=y)

    clf = GradientBoostingClassifier(n_estimators=100, max_depth=3,
        learning_rate=0.1, subsample=0.8, min_samples_leaf=50, random_state=42)
    clf.fit(X_tr, y_tr)

    yp = clf.predict_proba(X_te)[:, 1]
    yd = (yp > 0.5).astype(int)

    print("=" * 90)
    print("OVERALL")
    print("=" * 90)
    print(classification_report(y_te, yd, target_names=["benign", "malicious"], digits=4))
    print(f"ROC AUC: {roc_auc_score(y_te, yp):.4f}")

    # Per-campaign
    test_camps = camps[idx_te]
    all_c = load_all_campaigns()
    unique_camps = sorted(set(c for c in test_camps if c != "benign"))

    if unique_camps:
        print()
        print("=" * 90)
        print(f"{'Campaign':<40s} {'#Te':>5s} {'Mal':>4s} {'Ben':>4s} "
              f"{'TP':>4s} {'FP':>4s} {'FN':>4s} {'TN':>4s} "
              f"{'Prec':>7s} {'Rec':>7s} {'F1':>7s}")
        print("-" * 90)

        results = []
        for cid in unique_camps:
            mask = test_camps == cid
            if mask.sum() == 0:
                continue
            cy = y_te[mask]
            cp = yd[mask]
            tp = int(((cy == 1) & (cp == 1)).sum())
            fp = int(((cy == 0) & (cp == 1)).sum())
            fn = int(((cy == 1) & (cp == 0)).sum())
            tn = int(((cy == 0) & (cp == 0)).sum())
            prec = tp / max(tp + fp, 1)
            rec = tp / max(tp + fn, 1)
            f1 = 2 * prec * rec / max(prec + rec, 1e-10)
            n_mal = int((cy == 1).sum())
            n_ben = int((cy == 0).sum())

            name = all_c.get(cid, {}).get("full_name", cid)[:38]
            print(f"  {name:<38s} {mask.sum():>5d} {n_mal:>4d} {n_ben:>4d} "
                  f"{tp:>4d} {fp:>4d} {fn:>4d} {tn:>4d} "
                  f"{prec:>7.4f} {rec:>7.4f} {f1:>7.4f}")
            results.append(f1)

        if results:
            print("-" * 90)
            print(f"  Per-campaign F1: mean={np.mean(results):.4f} "
                  f"std={np.std(results):.4f} "
                  f"[{np.min(results):.4f}, {np.max(results):.4f}]")


# ═══════════════════════════════════════════════════════════════════════════
# COMMAND: judge
# ═══════════════════════════════════════════════════════════════════════════

def cmd_judge(args):
    """Judge fragments with Opus 4.6 (or simulated)."""
    from fragbench_judge_rl import OpusJudge, SimulatedJudge

    with open(args.input) as f:
        samples = json.load(f) if args.input.endswith(".json") else \
                  [json.loads(l) for l in f]

    judge = OpusJudge() if args.use_api else SimulatedJudge()
    judged = judge.judge_dataset(samples)

    with open(args.output, "w") as f:
        json.dump(judged, f)
    print(f"Saved: {args.output}")


# ═══════════════════════════════════════════════════════════════════════════
# COMMAND: scale
# ═══════════════════════════════════════════════════════════════════════════

def cmd_scale(args):
    """Show scaling info for different dataset sizes."""
    from fragbench_scalable import compute_stats

    sizes_str = args.sizes.split(",")
    size_map = {"100": 100, "1K": 1000, "10K": 10000, "100K": 100000,
                "1M": 1000000, "10M": 10000000, "100M": 100000000, "1B": 1000000000}

    print(f"{'Size':>10s} {'Actual':>14s} {'Per Camp/Class':>15s} "
          f"{'Train':>14s} {'Test':>14s}")
    print("-" * 70)

    for s in sizes_str:
        s = s.strip()
        if s in size_map:
            n = size_map[s]
        else:
            try:
                n = int(s.replace(",", ""))
            except ValueError:
                print(f"  {s}: unknown size (use 100, 1K, 100K, 1M, 100M, 1B)")
                continue
        stats = compute_stats(n)
        print(f"{s.strip():>10s} {stats['actual_size']:>14,} "
              f"{stats['per_campaign_per_class']:>15,} "
              f"{stats['total_train']:>14,} {stats['total_test']:>14,}")


# ═══════════════════════════════════════════════════════════════════════════
# COMMAND: viz
# ═══════════════════════════════════════════════════════════════════════════

def cmd_viz(args):
    """Export visualization data for the dashboard."""
    all_c = load_all_campaigns()
    chains = load_chains()

    viz = {"campaigns": [], "sources": {}, "mitre_tactics": {},
           "categories": {"confirmed": 0, "hypothetical": 0}}

    for cid in sorted(all_c.keys()):
        c = all_c[cid]
        tasks = []
        mitre_set = set()
        for t in c["tasks"]:
            tactic = t.get("mitre", "Unknown")
            mitre_set.add(tactic)
            viz["mitre_tactics"][tactic] = viz["mitre_tactics"].get(tactic, 0) + 1
            tasks.append({"name": t["name"][:60], "mitre": tactic,
                          "mitre_id": t.get("mitre_id", ""),
                          "n_prompts": len(t["prompts"]), "frag_range": list(t["frags"])})

        cat = c.get("category", "confirmed")
        viz["categories"][cat] = viz["categories"].get(cat, 0) + 1
        viz["sources"][c["source"]] = viz["sources"].get(c["source"], 0) + 1

        viz["campaigns"].append({
            "id": cid, "name": c["full_name"], "source": c["source"],
            "category": cat, "n_tasks": len(tasks),
            "n_prompts": sum(t["n_prompts"] for t in tasks),
            "mitre_tactics": sorted(mitre_set), "tasks": tasks,
        })

    viz["chains"] = [{"id": k, "name": v["name"], "steps": len(v["steps"]),
                      "source": v["source_incident"]}
                     for k, v in chains.items()]

    with open(args.output, "w") as f:
        json.dump(viz, f, indent=2)
    print(f"Saved: {args.output}")
    print(f"  Campaigns: {len(viz['campaigns'])}")
    print(f"  Sources: {viz['sources']}")
    print(f"  Chains: {len(viz['chains'])}")


# ═══════════════════════════════════════════════════════════════════════════
# COMMAND: info
# ═══════════════════════════════════════════════════════════════════════════

def cmd_info(args):
    """Show dataset info: all campaigns, tasks, prompts."""
    all_c = load_all_campaigns()
    campaigns = filter_campaigns(all_c, args.campaigns)

    total_tasks = 0
    total_prompts = 0
    for cid in sorted(campaigns.keys()):
        c = campaigns[cid]
        n_tasks = len(c["tasks"])
        n_prompts = sum(len(t["prompts"]) for t in c["tasks"])
        total_tasks += n_tasks
        total_prompts += n_prompts
        cat = "✓" if c.get("category", "confirmed") == "confirmed" else "~"

        print(f"{cat} {cid} {c['full_name']:<40s} {c['source']:<16s} "
              f"tasks={n_tasks} prompts={n_prompts}")

        if args.verbose:
            for ti, t in enumerate(c["tasks"]):
                print(f"    Task {ti+1}: [{t.get('mitre_id','')}] {t['name'][:60]}")
                for pi, p in enumerate(t["prompts"]):
                    print(f"      {pi+1}. {p[:80]}...")

    print(f"\nTotal: {len(campaigns)} campaigns, {total_tasks} tasks, {total_prompts} prompts")


# ═══════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def _write_output(stream, output_path, fmt, expected_count):
    """Write samples to file in specified format."""
    import gzip

    if fmt == "json":
        samples = list(stream)
        with open(output_path, "w") as f:
            json.dump(samples, f, indent=2 if len(samples) <= 1000 else None)
    elif fmt == "jsonl":
        with open(output_path, "w") as f:
            for s in stream:
                f.write(json.dumps(s) + "\n")
    elif fmt == "jsonl_gz":
        with gzip.open(output_path, "wt", compresslevel=6) as f:
            for s in stream:
                f.write(json.dumps(s) + "\n")

    size = os.path.getsize(output_path)
    print(f"  Output: {output_path} ({size/1e6:.1f} MB)")


# ═══════════════════════════════════════════════════════════════════════════
# CLI PARSER
# ═══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="FragBench — Unified Dataset Generator for LLM Fragmentation Attacks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s info --campaigns all                          # list all campaigns
  %(prog)s info --campaigns confirmed --verbose          # show task details

  %(prog)s generate --campaigns all --size 1000          # basic dataset
  %(prog)s generate --campaigns INC-001,INC-014 --size 500

  %(prog)s hard --size 10000 --output hard_10k.json      # 100%% ASR dataset
  %(prog)s rl --size 1000 --rounds 10 --method policy    # REINFORCE RL
  %(prog)s rl --size 1000 --rounds 10 --method llm       # LLM-generative RL

  %(prog)s eval --input dataset.json                     # F1 + per-campaign
  %(prog)s judge --input dataset.json --output judged.json

  %(prog)s scale --sizes 100,100K,1M,100M,1B
  %(prog)s viz --output dashboard.json
""")

    sub = parser.add_subparsers(dest="command")

    # ── info ──
    p = sub.add_parser("info", help="List campaigns and tasks")
    p.add_argument("--campaigns", default="all",
                   help="all | confirmed | hypothetical | INC-001,INC-002,...")
    p.add_argument("--verbose", "-v", action="store_true")

    # ── generate ──
    p = sub.add_parser("generate", help="Generate dataset")
    p.add_argument("--campaigns", default="all")
    p.add_argument("--size", type=int, default=100,
                   help="Samples PER CAMPAIGN (each campaign gets exactly this many)")
    p.add_argument("--output", default="fragbench_dataset.json")
    p.add_argument("--format", default="json", choices=["json", "jsonl", "jsonl_gz"])
    p.add_argument("--seed", type=int, default=42)

    # ── hard ──
    p = sub.add_parser("hard", help="Mode 1: pre-hardened 100% ASR")
    p.add_argument("--size", type=int, default=100,
                   help="Samples PER CAMPAIGN (malicious + benign, so size/2 each)")
    p.add_argument("--output", default="fragbench_hard.json")
    p.add_argument("--seed", type=int, default=42)

    # ── rl ──
    p = sub.add_parser("rl", help="Mode 2: RL trajectory")
    p.add_argument("--size", type=int, default=100,
                   help="Samples PER CAMPAIGN (malicious + benign, so size/2 each)")
    p.add_argument("--rounds", type=int, default=10)
    p.add_argument("--output_dir", default="rl_checkpoints")
    p.add_argument("--method", default="policy",
                   choices=["policy", "llm", "rules"],
                   help="policy=REINFORCE, llm=LLM-generative, rules=rule-based")
    p.add_argument("--use_api", action="store_true",
                   help="Use real Opus 4.6 judge + Sonnet 4.6 rewriter")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--bootstrap_db",
                   default=None,
                   help="Path to a JSONL or JSON corpus of prior successful "
                        "rewrites (e.g. rl_checkpoints/policies_db.jsonl). "
                        "Loaded into StrategyMemory.successes so the rewriter "
                        "uses them as in-context examples on round 1, "
                        "transferring learned policies across runs.")

    # ── eval ──
    p = sub.add_parser("eval", help="Evaluate dataset (F1 + per-campaign)")
    p.add_argument("--input", required=True)

    # ── judge ──
    p = sub.add_parser("judge", help="Judge fragments with Opus 4.6")
    p.add_argument("--input", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--use_api", action="store_true")

    # ── scale ──
    p = sub.add_parser("scale", help="Show scaling info")
    p.add_argument("--sizes", default="100,100K,1M,100M,1B")

    # ── viz ──
    p = sub.add_parser("viz", help="Export visualization data")
    p.add_argument("--output", default="fragbench_viz.json")

    args = parser.parse_args()

    if args.command == "info":
        cmd_info(args)
    elif args.command == "generate":
        cmd_generate(args)
    elif args.command == "hard":
        cmd_hard(args)
    elif args.command == "rl":
        cmd_rl(args)
    elif args.command == "eval":
        cmd_eval(args)
    elif args.command == "judge":
        cmd_judge(args)
    elif args.command == "scale":
        cmd_scale(args)
    elif args.command == "viz":
        cmd_viz(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
