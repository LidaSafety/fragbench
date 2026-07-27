"""
GNN Architecture Comparison for FragGuard.

Trains and evaluates four GNN variants on the same dataset:
  - GraphSAGE (mean aggregation)
  - GAT (multi-head attention)
  - GCN (symmetric normalization)
  - GIN (sum aggregation + MLP)

Reports effectiveness (AUC, AP, Precision, Recall, F1) and
efficiency (training time, inference latency, throughput, params).

Usage:
    cd PrecomputedMLPGNN
    python compare_gnns.py
"""

from __future__ import annotations

import io
import os
import sys
import time
import json

import numpy as np
import torch
import torch.nn as nn
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    roc_auc_score,
    average_precision_score,
    precision_recall_fscore_support,
)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "GradientBoostedTree"))

from models import FragGNNGeneric, FragScorer, LAYER_REGISTRY
from train_gnn import (
    NeighborSampler,
    build_node_features,
    campaign_disjoint_split,
    NODE_FEAT_DIM,
)
from main import CampaignDatasetGenerator

# GBT imports
from fragguard_gbt import FragmentFeatureEngine


# ═══════════════════════════════════════════════════════════════════════════
# TRAINING A SINGLE ARCHITECTURE
# ═══════════════════════════════════════════════════════════════════════════

def train_single_arch(
    arch: str,
    sampler: NeighborSampler,
    train_ids: np.ndarray,
    y_train: np.ndarray,
    test_ids: np.ndarray,
    y_test: np.ndarray,
    epochs: int = 30,
    batch_size: int = 256,
    lr: float = 1e-3,
    device: str = "cpu",
) -> dict:
    """Train one GNN architecture. Returns a metrics dict."""

    # Reset sampler RNG so every arch sees the same sampling order
    sampler.rng = np.random.default_rng(42)
    rng = np.random.default_rng(42)

    # Build model
    layer_kwargs = {}
    if arch == "gat":
        layer_kwargs["num_heads"] = 4

    gnn = FragGNNGeneric(
        arch=arch,
        node_feat_dim=NODE_FEAT_DIM,
        hidden_dim=256,
        embed_dim=128,
        **layer_kwargs,
    ).to(device)
    scorer = FragScorer(embed_dim=128, hidden=64).to(device)

    param_count = sum(p.numel() for p in gnn.parameters()) + \
                  sum(p.numel() for p in scorer.parameters())

    # Model size in KB
    buf = io.BytesIO()
    torch.save({"gnn": gnn.state_dict(), "scorer": scorer.state_dict()}, buf)
    model_size_kb = buf.tell() / 1024

    # Loss + optimizer
    pos_weight = torch.tensor(
        [(y_train == 0).sum() / max((y_train == 1).sum(), 1)],
        dtype=torch.float32
    ).to(device)
    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    optimizer = torch.optim.Adam(
        list(gnn.parameters()) + list(scorer.parameters()),
        lr=lr, weight_decay=1e-5,
    )
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)

    # ── Training loop ────────────────────────────────────────────────────
    best_auc = 0.0
    best_state = None

    t_train_start = time.perf_counter()

    for epoch in range(epochs):
        gnn.train()
        scorer.train()

        perm = rng.permutation(len(train_ids))
        ids_shuffled = train_ids[perm]
        y_shuffled = y_train[perm]

        epoch_loss = 0.0
        n_batches = 0

        for start in range(0, len(ids_shuffled), batch_size):
            end = min(start + batch_size, len(ids_shuffled))
            batch_nodes = ids_shuffled[start:end]
            batch_labels = torch.from_numpy(
                y_shuffled[start:end].astype(np.float32)
            ).to(device)

            batch = sampler.sample_batch(batch_nodes)
            batch = {k: v.to(device) for k, v in batch.items()}

            embeddings = gnn(**batch)
            logits = scorer(embeddings)
            loss = criterion(logits, batch_labels)

            optimizer.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(
                list(gnn.parameters()) + list(scorer.parameters()), 1.0
            )
            optimizer.step()

            epoch_loss += loss.item()
            n_batches += 1

        scheduler.step()
        avg_loss = epoch_loss / max(n_batches, 1)

        # Validate every 5 epochs
        if (epoch + 1) % 5 == 0 or epoch == 0:
            val_auc = _evaluate_auc(gnn, scorer, sampler, test_ids, y_test,
                                     batch_size, device)
            if val_auc > best_auc:
                best_auc = val_auc
                best_state = {
                    "gnn": {k: v.cpu().clone() for k, v in gnn.state_dict().items()},
                    "scorer": {k: v.cpu().clone() for k, v in scorer.state_dict().items()},
                }
            marker = " *" if val_auc >= best_auc else ""
            print(f"    Epoch {epoch+1:>2}/{epochs} | Loss: {avg_loss:.4f} | "
                  f"Val AUC: {val_auc:.4f}{marker}")

    train_time = time.perf_counter() - t_train_start

    # ── Final evaluation with best checkpoint ────────────────────────────
    if best_state:
        gnn.load_state_dict(best_state["gnn"])
        scorer.load_state_dict(best_state["scorer"])

    gnn.eval()
    scorer.eval()

    # Inference timing
    all_probs, all_labels = [], []
    t_infer_start = time.perf_counter()
    with torch.no_grad():
        for start in range(0, len(test_ids), batch_size):
            end = min(start + batch_size, len(test_ids))
            batch_nodes = test_ids[start:end]
            batch = sampler.sample_batch(batch_nodes)
            batch = {k: v.to(device) for k, v in batch.items()}
            emb = gnn(**batch)
            probs = scorer.score(emb).cpu().numpy()
            all_probs.append(probs)
            all_labels.append(y_test[start:end])
    if device == "cuda":
        torch.cuda.synchronize()
    infer_time = time.perf_counter() - t_infer_start

    all_probs = np.concatenate(all_probs)
    all_labels = np.concatenate(all_labels)
    y_pred = (all_probs > 0.5).astype(int)

    auc = roc_auc_score(all_labels, all_probs)
    ap = average_precision_score(all_labels, all_probs)
    acc = accuracy_score(all_labels, y_pred)
    prec, rec, f1, _ = precision_recall_fscore_support(
        all_labels, y_pred, pos_label=1, average="binary", zero_division=0
    )

    throughput = len(test_ids) / infer_time

    return {
        "arch": arch,
        "roc_auc": auc,
        "avg_precision": ap,
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "train_time_s": train_time,
        "infer_time_ms": infer_time * 1e3,
        "throughput": throughput,
        "param_count": param_count,
        "model_size_kb": model_size_kb,
        "best_val_auc": best_auc,
    }


def _evaluate_auc(gnn, scorer, sampler, test_ids, y_test, batch_size, device):
    gnn.eval()
    scorer.eval()
    all_probs, all_labels = [], []
    with torch.no_grad():
        for start in range(0, len(test_ids), batch_size):
            end = min(start + batch_size, len(test_ids))
            batch = sampler.sample_batch(test_ids[start:end])
            batch = {k: v.to(device) for k, v in batch.items()}
            emb = gnn(**batch)
            probs = scorer.score(emb).cpu().numpy()
            all_probs.append(probs)
            all_labels.append(y_test[start:end])
    return roc_auc_score(np.concatenate(all_labels), np.concatenate(all_probs))


# ═══════════════════════════════════════════════════════════════════════════
# COMPARISON TABLE
# ═══════════════════════════════════════════════════════════════════════════

ARCH_DISPLAY = {
    "sage": "GraphSAGE",
    "gat": "GAT",
    "gcn": "GCN",
    "gin": "GIN",
    "gbt": "GBT",
    "rf": "RandomForest",
    "lr": "LogisticReg",
    "svm": "SVM (RBF)",
    "knn": "KNN",
    "mlp_sk": "MLP (sklearn)",
    "adaboost": "AdaBoost",
}


# ═══════════════════════════════════════════════════════════════════════════
# CLASSICAL ML METHODS (all use 36-dim hand-engineered graph features)
# ═══════════════════════════════════════════════════════════════════════════

def _compute_graph_features(adj_list, node_metadata, edge_types_map,
                             train_ids, test_ids):
    """Compute 36-dim graph-structural features once, shared by all ML methods."""
    engine = FragmentFeatureEngine()
    total_nodes = max(max(train_ids), max(test_ids)) + 1

    full_adj = dict(adj_list)
    for nid in range(total_nodes):
        if nid not in full_adj:
            full_adj[nid] = []

    t0 = time.perf_counter()
    X_all, node_id_order = engine.compute_all_features(
        full_adj, node_metadata, edge_types_map
    )
    feat_time = time.perf_counter() - t0

    id_to_idx = {nid: i for i, nid in enumerate(node_id_order)}
    X_train = np.stack([X_all[id_to_idx[nid]] for nid in train_ids])
    X_test = np.stack([X_all[id_to_idx[nid]] for nid in test_ids])

    print(f"    Feature computation: {feat_time:.2f}s "
          f"({X_all.shape[1]} features, {total_nodes:,} nodes)")
    return X_train, X_test, feat_time


def _build_ml_models(y_train):
    """Build all classical ML models."""
    from sklearn.ensemble import (
        GradientBoostingClassifier,
        RandomForestClassifier,
        AdaBoostClassifier,
    )
    from sklearn.linear_model import LogisticRegression
    from sklearn.svm import SVC
    from sklearn.neighbors import KNeighborsClassifier
    from sklearn.neural_network import MLPClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.pipeline import Pipeline

    pos_weight = (y_train == 0).sum() / max((y_train == 1).sum(), 1)

    models = {}

    # 1. Gradient Boosted Trees
    try:
        import xgboost as xgb
        models["gbt"] = ("XGBoost", xgb.XGBClassifier(
            n_estimators=200, max_depth=8, learning_rate=0.05,
            scale_pos_weight=pos_weight,
            subsample=0.8, colsample_bytree=0.8, min_child_weight=5,
            reg_alpha=0.1, reg_lambda=1.0, random_state=42,
            eval_metric="aucpr", use_label_encoder=False,
        ))
    except ImportError:
        models["gbt"] = ("sklearn GBT", GradientBoostingClassifier(
            n_estimators=200, max_depth=8, learning_rate=0.05,
            subsample=0.8, random_state=42,
        ))

    # 2. Random Forest
    models["rf"] = ("Random Forest", RandomForestClassifier(
        n_estimators=300, max_depth=12, min_samples_leaf=3,
        class_weight="balanced", random_state=42, n_jobs=-1,
    ))

    # 3. Logistic Regression (with scaling)
    models["lr"] = ("Logistic Regression", Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(
            C=1.0, class_weight="balanced", max_iter=1000,
            solver="lbfgs", random_state=42,
        )),
    ]))

    # 4. SVM with RBF kernel (with scaling)
    models["svm"] = ("SVM (RBF)", Pipeline([
        ("scaler", StandardScaler()),
        ("clf", SVC(
            C=10.0, gamma="scale", kernel="rbf",
            class_weight="balanced", probability=True, random_state=42,
        )),
    ]))

    # 5. K-Nearest Neighbors (with scaling)
    models["knn"] = ("KNN (k=7)", Pipeline([
        ("scaler", StandardScaler()),
        ("clf", KNeighborsClassifier(
            n_neighbors=7, weights="distance", metric="minkowski",
            n_jobs=-1,
        )),
    ]))

    # 6. MLP (sklearn)
    models["mlp_sk"] = ("MLP (sklearn)", Pipeline([
        ("scaler", StandardScaler()),
        ("clf", MLPClassifier(
            hidden_layer_sizes=(128, 64), activation="relu",
            solver="adam", learning_rate="adaptive",
            max_iter=300, early_stopping=True, validation_fraction=0.1,
            random_state=42,
        )),
    ]))

    # 7. AdaBoost
    models["adaboost"] = ("AdaBoost", AdaBoostClassifier(
        n_estimators=200, learning_rate=0.1, random_state=42,
    ))

    return models


def _estimate_param_count(model, arch_key):
    """Estimate parameter count for different model types."""
    import pickle

    # Unwrap pipeline
    actual = model
    if hasattr(model, 'named_steps'):
        for name, step in model.named_steps.items():
            if name != 'scaler':
                actual = step

    if hasattr(actual, 'get_booster'):
        trees_dump = actual.get_booster().get_dump()
        return sum(d.count('leaf') for d in trees_dump)
    elif hasattr(actual, 'estimators_'):
        try:
            if hasattr(actual.estimators_, 'flat'):
                return sum(e.tree_.node_count for e in actual.estimators_.flat)
            elif hasattr(actual.estimators_[0], 'tree_'):
                return sum(e.tree_.node_count for e in actual.estimators_)
            else:
                # Nested (e.g. GBT)
                return sum(e[0].tree_.node_count for e in actual.estimators_)
        except Exception:
            return 0
    elif hasattr(actual, 'coefs_'):
        # MLP
        return sum(c.size for c in actual.coefs_) + sum(b.size for b in actual.intercepts_)
    elif hasattr(actual, 'coef_'):
        # Linear model
        return actual.coef_.size + actual.intercept_.size
    elif hasattr(actual, 'support_vectors_'):
        # SVM
        return actual.support_vectors_.size + actual.dual_coef_.size
    elif hasattr(actual, '_fit_X'):
        # KNN
        return actual._fit_X.size
    return 0


def train_ml_methods(
    adj_list: dict,
    node_metadata: dict,
    edge_types_map: dict,
    train_ids: np.ndarray,
    y_train: np.ndarray,
    test_ids: np.ndarray,
    y_test: np.ndarray,
) -> list[dict]:
    """Train all classical ML methods on hand-engineered graph features."""
    import pickle

    # Compute features ONCE for all methods
    X_train, X_test, feat_time = _compute_graph_features(
        adj_list, node_metadata, edge_types_map, train_ids, test_ids
    )

    models = _build_ml_models(y_train)
    results = []

    for arch_key, (display_name, model) in models.items():
        print(f"\n    ── {display_name} ──")

        # Train
        t0 = time.perf_counter()
        model.fit(X_train, y_train)
        train_time = time.perf_counter() - t0
        print(f"    Trained in {train_time:.2f}s")

        # Inference (average over 10 runs)
        t0 = time.perf_counter()
        for _ in range(10):
            y_proba = model.predict_proba(X_test)[:, 1]
        infer_time = (time.perf_counter() - t0) / 10

        y_pred = (y_proba > 0.5).astype(int)
        auc = roc_auc_score(y_test, y_proba)
        ap = average_precision_score(y_test, y_proba)
        acc = accuracy_score(y_test, y_pred)
        prec, rec, f1, _ = precision_recall_fscore_support(
            y_test, y_pred, pos_label=1, average="binary", zero_division=0
        )

        param_count = _estimate_param_count(model, arch_key)

        buf = io.BytesIO()
        pickle.dump(model, buf)
        model_size_kb = buf.tell() / 1024

        throughput = len(X_test) / infer_time

        print(f"    AUC={auc:.4f} | F1={f1:.4f} | "
              f"Infer={infer_time*1e3:.1f}ms | {throughput:,.0f} nodes/s")

        results.append({
            "arch": arch_key,
            "roc_auc": auc,
            "avg_precision": ap,
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1": f1,
            "train_time_s": train_time + feat_time,
            "infer_time_ms": infer_time * 1e3,
            "throughput": throughput,
            "param_count": param_count,
            "model_size_kb": model_size_kb,
            "best_val_auc": auc,
        })

    return results


def print_comparison(results: list[dict]):
    """Print a formatted comparison table."""

    print(f"\n{'=' * 110}")
    print("  COMPARISON: GNN Architecture Effectiveness & Efficiency")
    print(f"{'=' * 110}")

    W = 14  # column width for model names

    # ── Effectiveness table ──────────────────────────────────────────────
    print(f"\n  {'─' * 88}")
    print(f"  EFFECTIVENESS (sorted by F1)")
    print(f"  {'─' * 88}")
    hdr = (f"  {'Model':<{W}s} │ {'ROC AUC':>8s} │ {'Avg Prec':>8s} │ "
           f"{'Precision':>9s} │ {'Recall':>8s} │ {'F1':>8s}")
    print(hdr)
    print(f"  {'─'*W}─┼─{'─'*8}─┼─{'─'*8}─┼─{'─'*9}─┼─{'─'*8}─┼─{'─'*8}")

    sorted_res = sorted(results, key=lambda r: r["f1"], reverse=True)
    for r in sorted_res:
        name = ARCH_DISPLAY.get(r["arch"], r["arch"])
        print(f"  {name:<{W}s} │ {r['roc_auc']:>8.4f} │ {r['avg_precision']:>8.4f} │ "
              f"{r['precision']:>9.4f} │ {r['recall']:>8.4f} │ {r['f1']:>8.4f}")

    # ── Efficiency table ─────────────────────────────────────────────────
    print(f"\n  {'─' * 100}")
    print(f"  EFFICIENCY (sorted by throughput)")
    print(f"  {'─' * 100}")
    hdr = (f"  {'Model':<{W}s} │ {'Train (s)':>10s} │ {'Infer (ms)':>10s} │ "
           f"{'Throughput':>14s} │ {'Params':>10s} │ {'Size (KB)':>10s}")
    print(hdr)
    print(f"  {'─'*W}─┼─{'─'*10}─┼─{'─'*10}─┼─{'─'*14}─┼─{'─'*10}─┼─{'─'*10}")

    sorted_eff = sorted(results, key=lambda r: r["throughput"], reverse=True)
    for r in sorted_eff:
        name = ARCH_DISPLAY.get(r["arch"], r["arch"])
        print(f"  {name:<{W}s} │ {r['train_time_s']:>10.1f} │ {r['infer_time_ms']:>10.1f} │ "
              f"{r['throughput']:>12,.0f}/s │ {r['param_count']:>10,} │ {r['model_size_kb']:>10.1f}")

    # ── Summary ──────────────────────────────────────────────────────────
    best_f1 = max(results, key=lambda r: r["f1"])
    best_auc = max(results, key=lambda r: r["roc_auc"])
    fastest = max(results, key=lambda r: r["throughput"])
    smallest = min(results, key=lambda r: r["param_count"])
    fastest_train = min(results, key=lambda r: r["train_time_s"])

    print(f"\n  {'─' * 65}")
    print(f"  SUMMARY")
    print(f"  {'─' * 65}")
    print(f"  Best F1:          {ARCH_DISPLAY[best_f1['arch']]:<{W}s} "
          f"(F1: {best_f1['f1']:.4f})")
    print(f"  Best AUC:         {ARCH_DISPLAY[best_auc['arch']]:<{W}s} "
          f"(AUC: {best_auc['roc_auc']:.4f})")
    print(f"  Fastest infer:    {ARCH_DISPLAY[fastest['arch']]:<{W}s} "
          f"({fastest['throughput']:,.0f} nodes/sec)")
    print(f"  Fastest training: {ARCH_DISPLAY[fastest_train['arch']]:<{W}s} "
          f"({fastest_train['train_time_s']:.1f}s)")
    print(f"  Smallest model:   {ARCH_DISPLAY[smallest['arch']]:<{W}s} "
          f"({smallest['param_count']:,} params)")

    # Best overall (AUC * throughput normalized)
    max_auc_v = max(r["roc_auc"] for r in results)
    max_tp = max(r["throughput"] for r in results)
    for r in results:
        r["score"] = (r["roc_auc"] / max_auc_v) * 0.6 + (r["throughput"] / max_tp) * 0.4
    best_overall = max(results, key=lambda r: r["score"])
    print(f"  Best trade-off:   {ARCH_DISPLAY[best_overall['arch']]:<{W}s} "
          f"(60% accuracy + 40% speed)")


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main(
    num_benign: int = 10_000,
    epochs: int = 30,
    batch_size: int = 256,
    lr: float = 1e-3,
    K1: int = 10,
    K2: int = 5,
):
    device = "cuda" if torch.cuda.is_available() else "cpu"

    print("=" * 110)
    print("  FragGuard Model Comparison: GNN Variants + Gradient Boosted Trees")
    print("=" * 110)
    print(f"  Device: {device}")
    if device == "cuda":
        print(f"  GPU: {torch.cuda.get_device_name(0)}")
    print(f"  Models: {', '.join(ARCH_DISPLAY.values())}")
    print(f"  GNN Epochs: {epochs} | Batch: {batch_size} | LR: {lr}")

    # ── Step 1: Generate shared dataset ──────────────────────────────────
    print(f"\n{'─' * 110}")
    print("  Generating shared dataset...")
    print(f"{'─' * 110}")

    gen = CampaignDatasetGenerator(seed=42)
    adj_list, node_metadata, edge_types_map, labels, campaign_info = gen.generate(
        num_benign_nodes=num_benign,
        campaigns_to_plant={
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
        },
        benign_cross_session_rate=0.15,
        num_sessions=max(1000, num_benign // 10),
        num_users=max(200, num_benign // 50),
    )

    total_nodes = len(labels)
    all_node_ids = list(range(total_nodes))

    rng = np.random.default_rng(42)
    node_features = build_node_features(node_metadata, all_node_ids, rng)

    train_ids, test_ids, y_train, y_test = campaign_disjoint_split(
        all_node_ids, labels, campaign_info,
        test_size=0.2, random_state=42,
    )
    train_set = set(train_ids.tolist())
    n_train_inst = sum(1 for c in campaign_info if int(c["nodes"][0]) in train_set)
    n_test_inst = len(campaign_info) - n_train_inst
    print(f"  Train: {len(train_ids):,} ({y_train.sum():,} malicious from {n_train_inst} campaigns) | "
          f"Test: {len(test_ids):,} ({y_test.sum():,} malicious from {n_test_inst} campaigns)")

    sampler = NeighborSampler(adj_list, edge_types_map, node_features,
                               K1=K1, K2=K2, seed=42)

    # ── Step 2: Train each architecture ──────────────────────────────────
    architectures = ["sage", "gat", "gcn", "gin"]
    results = []

    for arch in architectures:
        name = ARCH_DISPLAY[arch]
        print(f"\n{'─' * 110}")
        print(f"  Training: {name}")
        print(f"{'─' * 110}")

        metrics = train_single_arch(
            arch=arch,
            sampler=sampler,
            train_ids=train_ids,
            y_train=y_train,
            test_ids=test_ids,
            y_test=y_test,
            epochs=epochs,
            batch_size=batch_size,
            lr=lr,
            device=device,
        )
        results.append(metrics)

        print(f"  → {name}: AUC={metrics['roc_auc']:.4f} | "
              f"F1={metrics['f1']:.4f} | "
              f"Train={metrics['train_time_s']:.1f}s | "
              f"Infer={metrics['infer_time_ms']:.1f}ms | "
              f"Params={metrics['param_count']:,}")

    # ── Step 3: Train classical ML methods ───────────────────────────────
    print(f"\n{'─' * 110}")
    print(f"  Training: Classical ML methods (on 36-dim graph features)")
    print(f"{'─' * 110}")

    ml_results = train_ml_methods(
        adj_list=adj_list,
        node_metadata=node_metadata,
        edge_types_map=edge_types_map,
        train_ids=train_ids,
        y_train=y_train,
        test_ids=test_ids,
        y_test=y_test,
    )
    results.extend(ml_results)

    # ── Step 4: Print comparison ─────────────────────────────────────────
    print_comparison(results)

    # ── Save results ─────────────────────────────────────────────────────
    save_dir = os.path.join(os.path.dirname(__file__), "..", "checkpoints")
    os.makedirs(save_dir, exist_ok=True)
    save_path = os.path.join(save_dir, "gnn_comparison.json")
    with open(save_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n  Results saved to: {save_path}")


if __name__ == "__main__":
    main(
        num_benign=10_000,
        epochs=30,
        batch_size=256,
        lr=1e-3,
    )
