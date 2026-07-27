"""
Edge-type ablation for FragBench Defense.

Reviewers (AC #2, zS9F, VL5J) asked which edge types carry the detection
signal, and whether the *cross-session* edges are necessary. This script
answers that by re-running the exact same training pipeline as
compare_gnns.py, but with the interaction graph restricted to a chosen
subset of edge types.

The intervention is a single, clean filter: we keep only edges whose type
id is in the condition's allowed set, applied identically to (a) the GNN
NeighborSampler and (b) the classical-ML graph-feature engine, so every
model in the panel sees the same ablated graph. Nothing else changes
(same seed, same split, same hyperparameters).

Edge-type ids follow models.EDGE_TYPES order:
    0 = data_flow       (within-session)
    1 = temporal        (within-session)
    2 = shared_resource (CROSS-session)
    3 = shared_session  (within-session)
    (4 = argument_similarity, CROSS-session — NOT built by the released
         generator, so it never appears; the drop_argument_similarity
         row is therefore identical to the full graph and is marked N/A.)

Run:
    cd PrecomputedMLPGNN
    python run_ablation.py                      # defaults: 10k benign, 30 epochs
    python run_ablation.py --num_benign 10000 --epochs 30
    python run_ablation.py --conditions full within_session_only cross_session_only

Output: a condition x model F1 table to stdout, plus
../checkpoints/edge_ablation.json
"""

from __future__ import annotations

import argparse
import json
import os

import numpy as np
import torch

from models import EDGE_TYPES  # ("data_flow","temporal","shared_resource","shared_session")
from train_gnn import (
    NeighborSampler,
    build_node_features,
    campaign_disjoint_split,
)
from compare_gnns import (
    train_single_arch,
    train_ml_methods,
    ARCH_DISPLAY,
)
from main import CampaignDatasetGenerator


# Name -> edge-type id, for readability.
TYPE_ID = {name: i for i, name in enumerate(EDGE_TYPES)}
WITHIN_SESSION = {TYPE_ID["data_flow"], TYPE_ID["temporal"], TYPE_ID["shared_session"]}
CROSS_SESSION = {TYPE_ID["shared_resource"]}  # argument_similarity (id 4) unimplemented
ALL_TYPES = set(range(len(EDGE_TYPES)))

# Reviewer-requested ablation conditions: name -> set of edge-type ids kept.
CONDITIONS = {
    "full": ALL_TYPES,                                   # all edges (baseline = Table 3)
    "within_session_only": WITHIN_SESSION,               # drop cross-session edges
    "cross_session_only": CROSS_SESSION,                 # drop within-session edges
    "drop_shared_resource": ALL_TYPES - {TYPE_ID["shared_resource"]},
    "no_edges": set(),                                   # per-node features only
    # "drop_argument_similarity": ALL_TYPES,  # no-op: arg_similarity never emitted
}

# Default plant matches compare_gnns.main so the "full" row reproduces the
# released defense numbers.
DEFAULT_PLANT = {
    "GTG-1002_espionage": 5,
    "GTG-2002_extortion": 8,
    "AI_RaaS_developer": 15,
    "PROMPTSTEAL_APT28": 10,
    "PROMPTFLUX": 8,
    "HONESTCUE": 8,
    "ScopeCreep": 12,
    "Russian_malware_clusters": 10,
    "MalTerminal": 10,
    "WormGPT_KawaiiGPT": 8,
}


def filter_edges(adj_list, edge_types_map, keep_types):
    """Return (adj_list, edge_types_map) restricted to edges whose type id
    is in keep_types. Edges with no recorded type default to 'temporal' (id
    1), matching NeighborSampler's own fallback, and are kept iff 1 in keep."""
    default_t = TYPE_ID["temporal"]
    f_adj = {}
    f_etm = {}
    for src, neighbors in adj_list.items():
        kept = []
        for dst in neighbors:
            t = edge_types_map.get((src, dst), edge_types_map.get((dst, src), default_t))
            if t in keep_types:
                kept.append(dst)
                f_etm[(src, dst)] = t
        f_adj[src] = kept
    return f_adj, f_etm


def _edge_count(adj_list):
    return sum(len(v) for v in adj_list.values())


def run(num_benign=10_000, epochs=30, batch_size=256, lr=1e-3,
        K1=10, K2=5, conditions=None, seed=42):
    device = "cuda" if torch.cuda.is_available() else "cpu"
    conditions = conditions or list(CONDITIONS.keys())

    print("=" * 100)
    print("  FragBench Defense — Edge-Type Ablation")
    print("=" * 100)
    print(f"  Device: {device} | benign nodes: {num_benign:,} | epochs: {epochs}")
    print(f"  Edge-type ids: " + ", ".join(f"{i}={n}" for i, n in enumerate(EDGE_TYPES)))
    print(f"  Conditions: {', '.join(conditions)}")

    # ── Generate the graph ONCE; ablations only filter its edges ──────────
    gen = CampaignDatasetGenerator(seed=seed)
    adj_list, node_metadata, edge_types_map, labels, campaign_info = gen.generate(
        num_benign_nodes=num_benign,
        campaigns_to_plant=DEFAULT_PLANT,
        benign_cross_session_rate=0.15,
        num_sessions=max(1000, num_benign // 10),
        num_users=max(200, num_benign // 50),
    )
    total_nodes = len(labels)
    all_node_ids = list(range(total_nodes))
    rng = np.random.default_rng(seed)
    node_features = build_node_features(node_metadata, all_node_ids, rng)

    # Same campaign-disjoint split reused across all conditions.
    train_ids, test_ids, y_train, y_test = campaign_disjoint_split(
        all_node_ids, labels, campaign_info, test_size=0.2, random_state=seed,
    )
    print(f"  Split: train {len(train_ids):,} ({int(y_train.sum())} mal) | "
          f"test {len(test_ids):,} ({int(y_test.sum())} mal)")
    print(f"  Full graph: {_edge_count(adj_list):,} directed edges")

    architectures = ["sage", "gat", "gcn", "gin"]
    table = {}  # condition -> {model_key: f1}

    for cond in conditions:
        keep = CONDITIONS[cond]
        f_adj, f_etm = filter_edges(adj_list, edge_types_map, keep)
        kept_names = sorted(EDGE_TYPES[i] for i in keep) or ["(none)"]
        print("\n" + "─" * 100)
        print(f"  CONDITION: {cond}  |  keep types: {kept_names}  |  "
              f"edges: {_edge_count(f_adj):,}")
        print("─" * 100)

        sampler = NeighborSampler(f_adj, f_etm, node_features, K1=K1, K2=K2, seed=seed)

        row = {}
        for arch in architectures:
            m = train_single_arch(
                arch=arch, sampler=sampler,
                train_ids=train_ids, y_train=y_train,
                test_ids=test_ids, y_test=y_test,
                epochs=epochs, batch_size=batch_size, lr=lr, device=device,
            )
            row[arch] = m["f1"]
            print(f"    {ARCH_DISPLAY[arch]:<12s} F1={m['f1']:.4f}  AUC={m['roc_auc']:.4f}")

        ml = train_ml_methods(
            adj_list=f_adj, node_metadata=node_metadata, edge_types_map=f_etm,
            train_ids=train_ids, y_train=y_train, test_ids=test_ids, y_test=y_test,
        )
        for r in ml:
            row[r["arch"]] = r["f1"]
            print(f"    {ARCH_DISPLAY.get(r['arch'], r['arch']):<12s} F1={r['f1']:.4f}")

        table[cond] = row

    # ── Summary table: rows = condition, cols = model ─────────────────────
    model_keys = architectures + [k for k in table[conditions[0]] if k not in architectures]
    print("\n" + "=" * 100)
    print("  EDGE-TYPE ABLATION — aggregate F1 (rows: condition, cols: model)")
    print("=" * 100)
    header = f"  {'condition':<22s}" + "".join(
        f"{ARCH_DISPLAY.get(k, k)[:9]:>10s}" for k in model_keys)
    print(header)
    print("  " + "-" * (len(header) - 2))
    for cond in conditions:
        cells = "".join(f"{table[cond].get(k, float('nan')):>10.3f}" for k in model_keys)
        print(f"  {cond:<22s}{cells}")
    print("\n  Note: drop_argument_similarity is omitted — the released generator")
    print("  never emits ARGUMENT_SIMILARITY (id 4) edges, so it equals 'full'.")

    save_dir = os.path.join(os.path.dirname(__file__), "..", "checkpoints")
    os.makedirs(save_dir, exist_ok=True)
    out = os.path.join(save_dir, "edge_ablation.json")
    with open(out, "w") as f:
        json.dump({"conditions": table, "model_keys": model_keys,
                   "edge_types": list(EDGE_TYPES)}, f, indent=2)
    print(f"\n  Saved: {out}")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--num_benign", type=int, default=10_000)
    p.add_argument("--epochs", type=int, default=30)
    p.add_argument("--batch_size", type=int, default=256)
    p.add_argument("--lr", type=float, default=1e-3)
    p.add_argument("--conditions", nargs="+", default=None,
                   choices=list(CONDITIONS.keys()))
    args = p.parse_args()
    run(num_benign=args.num_benign, epochs=args.epochs,
        batch_size=args.batch_size, lr=args.lr, conditions=args.conditions)
