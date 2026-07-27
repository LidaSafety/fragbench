#!/usr/bin/env python3
"""Leave-one-campaign-family-out over compare_gnns.main().

Reviewer #3 asks whether the headline split measures interpolation among
campaign templates rather than general cross-session detection:

    "report leave-one-campaign-out, leave-one-campaign-family-out, or grouped
     cross-validation in which no variant of the held-out campaign is seen
     during training. Results should include both aggregate performance and
     variation across held-out campaigns."

It is worth being precise about what the headline split does, because it is
not already family-disjoint: campaign_disjoint_split shuffles the 568 malicious
*instances*, so all 24 campaigns land on both sides. This script is therefore
new evidence, not a restatement of the existing protocol.

Scope is deliberately narrow. The 6-condition x 11-model edge ablation stays on
the single campaign-disjoint split; crossing the two would be ~1,600 trainings.
Here the graph condition is the primary one (full), with within_session_only as
the trend check that cross-session edges still carry their weight when the
held-out family is genuinely unseen.

The only thing replaced is the splitter -- same graph, same features, same
sampler, same models, same seeds, same epochs. main() runs once per
(fold, condition), unmodified.

Two properties make that a substitution rather than a rewrite:

  1. campaign_disjoint_split's benign partition is fold-invariant. It draws
     benign_perm from an rng whose state depends only on len(campaign_info),
     and derives benign_ids from `malicious_set`, the union of ALL instance
     nodes -- identical no matter which instances are held out. The original
     function is called once and each fold reuses its benign train/test
     partition verbatim; only the malicious side is overridden.

  2. A held-out family carries far fewer positives than the headline split's
     ~20%, so an unmatched fold's F1 would fall for prevalence reasons alone
     and be misread as a generalization failure. --match-prevalence subsamples
     the benign test pool to hold each fold's positive rate at the headline
     split's. AUC is reported either way and is prevalence-invariant.

Training never sees a held-out campaign in any form: campaign_info groups every
variation of an instance and the holdout is taken at family granularity, so all
six styles and nine seeds of every campaign in the family leave together. This
is asserted for every fold before any of them trains.

    python scripts/run_loco.py --benign benign_executed.json
    python scripts/run_loco.py --benign benign_executed.json --conditions full
    python scripts/run_loco.py --benign benign_executed.json --folds 0-2
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "fragbench-structural-graph-main" / "training"))
sys.path.insert(0, str(REPO / "fragbench-structural-graph-main" / "ablations"))
sys.path.insert(0, str(REPO / "scripts"))

import run_original_harness as ROH  # noqa: E402

# Campaign families. The seeds carry no family field, so the grouping is stated
# here rather than inferred: it is by operator objective, which is what
# "family" has to mean for a generalization claim -- a detector that has seen
# three ransomware campaigns has arguably seen the fourth's behaviour, whereas
# espionage recon is a different shape of trace.
FAMILIES = {
    "espionage_apt": ["GTG1002", "PROMPTSTEAL", "ad_discovery",
                      "RU_MALWARE_CLUSTERS", "SCOPE_CREEP"],
    "dprk_revenue": ["CORAL_SLEET", "JASPER_SLEET", "DPRK_FRAUD",
                     "UNC2970_OPERATION_DREAM_JOB"],
    "ransomware_extortion": ["LONDON_DRUGS_LOCKBIT", "ns_power_ransomware",
                             "NOCODE_RANSOMWARE", "VIBE_EXTORTION"],
    "phishing_fraud": ["AI_PHISHING", "COINBAIT", "TYCOON2FA",
                       "CLICKFIX_VIA_AI_CHAT", "OPERATION_FALSE_WITNESS",
                       "DEEPFAKE_ID_FRAUD"],
    "llm_enabled_malware": ["PROMPTFLUX", "HONESTCUE", "MALTERMINAL",
                            "QUIETVAULT", "WORMGPT_KAWAIIGPT"],
}

# Edge-type ids, as models.EDGE_TYPES orders them.
WITHIN, CROSS = {0, 1, 3}, {2, 4}
CONDITIONS = {"full": WITHIN | CROSS, "within_session_only": WITHIN,
              "cross_session_only": CROSS, "no_edges": set()}

# Display name -> results key, matching run_original_harness's table.
LABEL = {"svm": "SVM", "mlp_sk": "MLP", "gbt": "GBT", "rf": "RF", "lr": "LR",
         "knn": "KNN", "adaboost": "AdaBoost"}


def parse_folds(spec: str | None, n: int) -> list[int]:
    """'0-2' or '0,3' or None -> fold indices, for sharding across machines."""
    if not spec:
        return list(range(n))
    out: list[int] = []
    for part in spec.split(","):
        if "-" in part:
            a, b = part.split("-")
            out.extend(range(int(a), int(b) + 1))
        else:
            out.append(int(part))
    return [i for i in out if 0 <= i < n]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--malicious", default="dataset/combined/malicious.json")
    ap.add_argument("--benign", default="dataset/combined/benign.json")
    ap.add_argument("--malicious-sample", type=int)
    ap.add_argument("--benign-sample", type=int)
    ap.add_argument("--conditions", default="full,within_session_only",
                    help=f"comma-separated, from {sorted(CONDITIONS)}")
    ap.add_argument("--models", default="sage,gat,gbt,mlp_sk",
                    help="panel subset. 'all' runs the full 11-model panel and "
                         "costs roughly 2.5x this default per fold.")
    ap.add_argument("--epochs", type=int, default=30)
    ap.add_argument("--batch-size", type=int, default=256)
    ap.add_argument("--test-size", type=float, default=0.2,
                    help="sets the benign holdout fraction and the prevalence "
                         "target; the malicious holdout is the fold itself")
    ap.add_argument("--match-prevalence", action="store_true", default=True)
    ap.add_argument("--no-match-prevalence", dest="match_prevalence",
                    action="store_false")
    ap.add_argument("--folds", help="shard: '0-2' or '0,3' (default: all)")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--dry-run", action="store_true",
                    help="build the graph, check every fold's split for leakage "
                         "and print its shape, then stop without training")
    ap.add_argument("--out")
    args = ap.parse_args()

    conds = [c.strip() for c in args.conditions.split(",") if c.strip()]
    bad = [c for c in conds if c not in CONDITIONS]
    if bad:
        print(f"unknown conditions: {bad}", file=sys.stderr)
        return 2
    out = Path(args.out) if args.out else REPO / (
        f"results_loco_{Path(args.benign).stem}.json")

    ROH.prepare(args.malicious, args.benign,
                args.malicious_sample, args.benign_sample, args.seed)
    adj, meta, etypes, labels, campaign_info = ROH.TraceDatasetGenerator.graph
    camp_of = ROH.CAMPAIGN_OF

    # instance -> campaign -> family, then family -> the instances it owns
    inst_campaign = [camp_of[int(info["nodes"][0])] for info in campaign_info]
    # normalize_dataset lowercases campaign ids; the seed files do not
    fam_lookup = {c.lower(): f for f, cs in FAMILIES.items() for c in cs}
    group_of = {c: fam_lookup[c.lower()] for c in set(inst_campaign)
                if c.lower() in fam_lookup}
    missing = sorted(set(inst_campaign) - set(group_of))
    if missing:
        print(f"campaigns with no family assignment: {missing}", file=sys.stderr)
        return 2
    groups: dict[str, list[int]] = {}
    for i, c in enumerate(inst_campaign):
        groups.setdefault(group_of[c], []).append(i)
    names = sorted(groups)
    print(f"\nfamily folds: {len(names)}")
    for n in names:
        cs = sorted({inst_campaign[i] for i in groups[n]})
        pos = sum(len(campaign_info[i]["nodes"]) for i in groups[n])
        print(f"  {n:<24}{len(groups[n]):>4} inst {pos:>8,} ev   {', '.join(cs)}")

    # ── the headline split, called once; its benign side is fold-invariant ──
    import importlib
    mod = importlib.import_module("compare_gnns")
    base_split = mod.campaign_disjoint_split
    all_ids = list(range(len(labels)))
    b_tr, b_te, _, _ = base_split(all_ids, labels, campaign_info,
                                  test_size=args.test_size, random_state=args.seed)
    mal_nodes = {int(n) for info in campaign_info for n in info["nodes"]}
    benign_train = np.array([i for i in b_tr if i not in mal_nodes], dtype=np.int64)
    benign_pool = np.array([i for i in b_te if i not in mal_nodes], dtype=np.int64)
    n_mal_base = sum(1 for i in b_te if i in mal_nodes)
    ratio = len(benign_pool) / max(n_mal_base, 1)   # benign per positive
    print(f"\nheadline split: benign train={len(benign_train):,}  "
          f"benign test pool={len(benign_pool):,}  positives={n_mal_base:,}  "
          f"(benign per positive = {ratio:.2f})")

    state: dict = {}

    def fold_split(all_node_ids, labels_, campaign_info_, test_size=0.2,
                   random_state=42):
        """Original signature; holds out one family instead of a random sample
        of instances. The benign partition is the original function's."""
        held = set(state["instances"])
        mal_te, mal_tr = [], []
        for idx, info in enumerate(campaign_info_):
            (mal_te if idx in held else mal_tr).extend(int(n) for n in info["nodes"])
        if args.match_prevalence:
            k = min(len(benign_pool), int(round(len(mal_te) * ratio)))
            rng = np.random.default_rng(args.seed)
            b_test = benign_pool[rng.permutation(len(benign_pool))[:k]]
        else:
            b_test = benign_pool
        tr = np.array(sorted(mal_tr + benign_train.tolist()), dtype=np.int64)
        te = np.array(sorted(mal_te + b_test.tolist()), dtype=np.int64)
        state["test_ids"] = te
        return tr, te, labels_[tr], labels_[te]

    mod.campaign_disjoint_split = fold_split

    # ── edge condition: filter at the generator, so the GNN sampler and the
    # classical feature engine both see the same ablated graph (main() hands
    # them the same adj_list/edge_types_map it got from generate()) ──────────
    from run_ablation import filter_edges   # noqa: E402  original implementation

    class ConditionedGenerator(ROH.TraceDatasetGenerator):
        def generate(self, *a, **kw):
            g = ROH.TraceDatasetGenerator.graph
            keep = CONDITIONS[state["condition"]]
            if keep == CONDITIONS["full"]:
                return g
            f_adj, f_etm = filter_edges(g[0], g[2], keep)
            return (f_adj, g[1], f_etm, g[3], g[4])

    mod.CampaignDatasetGenerator = ConditionedGenerator

    # ── panel subsetting, by namespace substitution as elsewhere ───────────
    want = None if args.models == "all" else set(args.models.split(","))
    if want:
        _tsa, _bml = mod.train_single_arch, mod._build_ml_models

        def tsa(arch=None, *a, **kw):
            arch = arch or kw.pop("arch")
            if arch not in want:
                return {"arch": arch, "skipped": True, "f1": float("nan"),
                        "roc_auc": float("nan"), "accuracy": float("nan"),
                        "train_time_s": 0.0, "infer_time_ms": 0.0,
                        "param_count": 0}
            return _tsa(arch, *a, **kw)

        def bml(y_train):
            return {k: v for k, v in _bml(y_train).items() if k in want}

        mod.train_single_arch, mod._build_ml_models = tsa, bml

    # Per-event probabilities, for the per-campaign breakdown inside each fold.
    seen = ROH.install_capture(mod)

    # main() hands the full results list to print_comparison before writing its
    # fixed-path json, so reading it there means this script never depends on
    # checkpoints/gnn_comparison.json and a concurrent arm cannot clobber it.
    grabbed: list = []
    _pc = mod.print_comparison

    def pc(results, *a, **kw):
        # Architectures outside --models return a stub from train_single_arch;
        # drop them here so the original comparison table only ever ranks
        # models that actually trained.
        grabbed.append(results)
        return _pc([r for r in results if not r.get("skipped")], *a, **kw)

    mod.print_comparison = pc

    todo = parse_folds(args.folds, len(names))

    # Every fold's split is checked for leakage before any of them trains: a
    # held-out family must contribute zero nodes to train, or the whole
    # experiment answers a different question than the reviewer asked.
    state["condition"] = conds[0]
    print(f"\n  {'held out':<24}{'train':>10}{'test':>10}{'pos':>9}"
          f"{'pos rate':>10}   leak")
    for fi in todo:
        state["instances"] = groups[names[fi]]
        tr, te, _, _ = fold_split(all_ids, labels, campaign_info)
        held = {int(n) for i in groups[names[fi]] for n in campaign_info[i]["nodes"]}
        leak = len(held & set(tr.tolist()))
        print(f"  {names[fi]:<24}{len(tr):>10,}{len(te):>10,}"
              f"{int(labels[te].sum()):>9,}{labels[te].mean():>10.3f}"
              f"   {'OK' if leak == 0 else f'{leak} NODES'}")
        if leak:
            print("  leakage detected -- aborting", file=sys.stderr)
            return 2
    if args.dry_run:
        print("\n(dry run -- nothing trained)")
        return 0

    print(f"\nfolds {todo} x conditions {conds}  panel={args.models}  "
          f"match_prevalence={args.match_prevalence}")

    from sklearn.metrics import f1_score, accuracy_score   # noqa: E402

    runs: list = []
    for cond in conds:
        for fi in todo:
            name = names[fi]
            state["condition"], state["instances"] = cond, groups[name]
            grabbed.clear()
            seen.clear()
            t0 = time.perf_counter()
            print(f"\n{'#' * 110}\n#  {cond}  |  fold {fi}: hold out {name}\n{'#' * 110}")
            mod.main(epochs=args.epochs, batch_size=args.batch_size)

            res = [r for r in (grabbed[-1] if grabbed else []) if not r.get("skipped")]
            te = state["test_ids"]
            y, cm = labels[te], camp_of[te]

            # per-campaign F1 within the held-out family: that campaign's
            # positives + all benign test events, the Table 3 protocol. The
            # harness thresholds at > 0.5 (compare_gnns.py:196, 450).
            # GNN probabilities are filed under the display name, classical
            # ones under the arch key; accept either.
            def probs(arch):
                return seen.get(mod.ARCH_DISPLAY.get(arch, arch), seen.get(arch))

            cols = [r["arch"] for r in res if probs(r["arch"]) is not None
                    and len(np.asarray(probs(r["arch"]))) == len(te)]
            if len(cols) < len(res):
                print(f"  WARNING: no usable probabilities for "
                      f"{[r['arch'] for r in res if r['arch'] not in cols]}",
                      file=sys.stderr)
            per_campaign = []
            benign = y == 0
            for c in sorted({x for x, l in zip(cm, y) if l == 1}):
                sel = benign | ((y == 1) & (cm == c))
                row = {"campaign": c, "n_pos": int(((y == 1) & (cm == c)).sum())}
                for a in cols:
                    p = np.asarray(probs(a))
                    pred = (p[sel] > 0.5).astype(int)
                    row[f"{LABEL.get(a, a)}_F1"] = round(
                        float(f1_score(y[sel], pred, zero_division=0)), 4)
                    row[f"{LABEL.get(a, a)}_Ac"] = round(
                        float(accuracy_score(y[sel], pred)), 4)
                per_campaign.append(row)

            runs.append({"condition": cond, "fold": fi, "held_out": name,
                         "campaigns": sorted({inst_campaign[i] for i in groups[name]}),
                         "n_instances": len(groups[name]),
                         "n_test": int(len(te)), "n_pos": int(y.sum()),
                         "wall_s": round(time.perf_counter() - t0, 1),
                         "results": res, "per_campaign": per_campaign})

            for r in res:
                print(f"  [{cond}/{name}] {r['arch']:<8} "
                      f"F1={r.get('f1', float('nan')):.4f} "
                      f"AUC={r.get('roc_auc', float('nan')):.4f}")
            with open(out, "w") as fh:
                json.dump({"malicious": args.malicious, "benign": args.benign,
                           "mode": "leave_one_family_out",
                           "conditions": conds, "models": args.models,
                           "match_prevalence": args.match_prevalence,
                           "test_size": args.test_size, "epochs": args.epochs,
                           "runs": runs}, fh, indent=2)

    # ── summary: fold-level, then per-campaign, then mean/sd ───────────────
    if runs:
        archs = [r["arch"] for r in runs[0]["results"]]
        for cond in conds:
            rs = [r for r in runs if r["condition"] == cond]
            if not rs:
                continue
            print("\n" + "=" * 96)
            print(f"  LEAVE-ONE-FAMILY-OUT — condition: {cond}  ({len(rs)} folds)")
            print("=" * 96)
            print(f"  {'held-out family':<26}" + "".join(f"{a:>13}" for a in archs))
            for r in rs:
                cell = {x["arch"]: x.get("f1", float("nan")) for x in r["results"]}
                print(f"  {r['held_out']:<26}"
                      + "".join(f"{cell.get(a, float('nan')):>13.4f}" for a in archs))

            per = [(p, r) for r in rs for p in r["per_campaign"]]
            if per:
                print(f"\n  {'held-out campaign':<26}" + "".join(f"{a:>13}" for a in archs))
                for p, r in sorted(per, key=lambda t: t[0]["campaign"]):
                    print(f"  {p['campaign']:<26}"
                          + "".join(f"{p.get(f'{LABEL.get(a, a)}_F1', float('nan')):>13.4f}"
                                    for a in archs))
                print("  " + "-" * 92)
                for stat, fn in (("mean", np.nanmean), ("std", np.nanstd),
                                 ("min", np.nanmin), ("max", np.nanmax)):
                    vals = [fn([p.get(f"{LABEL.get(a, a)}_F1", float("nan"))
                                for p, _ in per]) for a in archs]
                    print(f"  {stat + ' (per campaign)':<26}"
                          + "".join(f"{v:>13.4f}" for v in vals))
        print(f"\n  wrote {out}")
        if len(todo) < len(names):
            print(f"  NOTE: shard only ({len(todo)}/{len(names)} folds); "
                  f"merge shards before quoting mean/std")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
