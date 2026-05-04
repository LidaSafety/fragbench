"""
GNN Training Pipeline for FragGuard.

Trains FragGNN + FragScorer jointly on the campaign dataset.

Pipeline:
  1. Generate fragment graph using CampaignDatasetGenerator
  2. Build neighbor-sampled batches (2-hop sampling)
  3. Train GNN + MLP scorer end-to-end with BCE loss
  4. Evaluate on held-out test set

Usage:
    cd PrecomputedMLPGNN
    python train_gnn.py
"""

from __future__ import annotations

import sys
import os
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import List, Tuple

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    roc_auc_score,
    average_precision_score,
    confusion_matrix,
)

# Add parent dir so we can import the GBT dataset generator
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "GradientBoostedTree"))
from models import FragGNN, FragScorer, EDGE_TYPES, NUM_EDGE_TYPES

# Import dataset generator
from main import CampaignDatasetGenerator, CAPABILITY_APIS


# ═══════════════════════════════════════════════════════════════════════════
# NEIGHBOR SAMPLER — converts the raw graph into GNN-consumable batches
# ═══════════════════════════════════════════════════════════════════════════

NODE_FEAT_DIM = 128  # dimensionality of input node features


def campaign_disjoint_split(
    all_node_ids: list,
    labels: np.ndarray,
    campaign_info: list,
    test_size: float = 0.2,
    random_state: int = 42,
):
    """
    Split node ids so that no planted-campaign instance appears in both train
    and test. Roughly ``test_size`` of the ``len(campaign_info)`` instances are
    held out wholesale (with their fragments) and the benign remainder is
    split independently at the same ratio.
    """
    rng = np.random.default_rng(random_state)
    num_instances = len(campaign_info)
    perm = rng.permutation(num_instances)
    n_test_inst = max(1, int(round(num_instances * test_size)))
    test_instances = set(perm[:n_test_inst].tolist())

    malicious_test_ids = []
    malicious_train_ids = []
    for idx, info in enumerate(campaign_info):
        bucket = malicious_test_ids if idx in test_instances else malicious_train_ids
        bucket.extend(int(n) for n in info["nodes"])

    malicious_set = set(malicious_train_ids) | set(malicious_test_ids)
    benign_ids = [int(n) for n in all_node_ids if int(n) not in malicious_set]
    benign_perm = rng.permutation(len(benign_ids))
    n_test_benign = int(round(len(benign_ids) * test_size))
    benign_test = [benign_ids[i] for i in benign_perm[:n_test_benign]]
    benign_train = [benign_ids[i] for i in benign_perm[n_test_benign:]]

    train_ids = np.array(sorted(malicious_train_ids + benign_train), dtype=np.int64)
    test_ids = np.array(sorted(malicious_test_ids + benign_test), dtype=np.int64)
    y_train = labels[train_ids]
    y_test = labels[test_ids]
    return train_ids, test_ids, y_train, y_test


def build_node_features(node_metadata: dict, node_ids: list, rng: np.random.Generator) -> dict:
    """
    Build a NODE_FEAT_DIM-dimensional feature vector for each node.

    We encode the metadata into a fixed-size vector:
      - [0:10]   capability one-hot (10 categories)
      - [10:14]  code-intrinsic: entropy, obfuscation, complexity, risk
      - [14:24]  API hash features (hash APIs into 10 buckets)
      - [24:128] random projection of the above for expressivity
    """
    cap_names = sorted(CAPABILITY_APIS.keys())
    cap_to_idx = {c: i for i, c in enumerate(cap_names)}
    num_caps = len(cap_names)

    features = {}
    raw_vecs = np.zeros((len(node_ids), 24), dtype=np.float32)

    for i, nid in enumerate(node_ids):
        meta = node_metadata.get(nid, {})
        vec = np.zeros(24, dtype=np.float32)

        # Capability one-hot
        for cap in meta.get("capabilities", set()):
            if cap in cap_to_idx:
                vec[cap_to_idx[cap]] = 1.0

        # Code-intrinsic features (normalized)
        vec[num_caps + 0] = meta.get("string_entropy", 3.8) / 8.0
        vec[num_caps + 1] = meta.get("obfuscation_score", 0.1)
        vec[num_caps + 2] = min(meta.get("code_complexity", 5.0), 30.0) / 30.0
        vec[num_caps + 3] = meta.get("risk_score", 0.1)

        # API hash buckets
        for api in meta.get("api_calls", set()):
            bucket = hash(api) % 10
            vec[14 + bucket] += 1.0
        # Normalize API buckets
        api_sum = vec[14:24].sum()
        if api_sum > 0:
            vec[14:24] /= api_sum

        raw_vecs[i] = vec

    # Random projection to NODE_FEAT_DIM
    proj = rng.standard_normal((24, NODE_FEAT_DIM)).astype(np.float32) * 0.1
    full_vecs = raw_vecs @ proj

    for i, nid in enumerate(node_ids):
        features[nid] = full_vecs[i]

    return features


class NeighborSampler:
    """
    Samples K1 one-hop and K2 two-hop neighbors per node.
    Produces batches ready for FragGNN.forward().
    """

    def __init__(
        self,
        adj_list: dict,
        edge_types_map: dict,
        node_features: dict,
        K1: int = 10,
        K2: int = 5,
        seed: int = 42,
    ):
        self.adj = adj_list
        self.edge_types = edge_types_map
        self.features = node_features
        self.K1 = K1
        self.K2 = K2
        self.rng = np.random.default_rng(seed)
        self.feat_dim = NODE_FEAT_DIM

        # Build undirected adjacency for sampling
        self.undirected = defaultdict(set)
        for src, neighbors in adj_list.items():
            for dst in neighbors:
                self.undirected[src].add(dst)
                self.undirected[dst].add(src)

    def _sample_neighbors(self, node: int, k: int) -> Tuple[List[int], List[int], List[bool]]:
        """Sample k neighbors for a node. Returns (neighbor_ids, edge_types, mask)."""
        neighbors = list(self.undirected.get(node, set()))

        if len(neighbors) == 0:
            return [0] * k, [0] * k, [False] * k

        if len(neighbors) >= k:
            chosen = self.rng.choice(neighbors, size=k, replace=False).tolist()
        else:
            chosen = neighbors + list(self.rng.choice(neighbors, size=k - len(neighbors), replace=True))

        edge_type_ids = []
        for nb in chosen:
            et = self.edge_types.get((node, nb), self.edge_types.get((nb, node), 1))
            edge_type_ids.append(et % NUM_EDGE_TYPES)

        mask = [True] * min(len(neighbors), k) + [False] * max(0, k - len(neighbors))
        return chosen, edge_type_ids, mask

    def sample_batch(self, node_ids: np.ndarray) -> dict:
        """
        Build a full 2-hop sampled batch for the given target nodes.

        Returns dict of tensors matching FragGNN.forward() signature.
        """
        B = len(node_ids)
        K1, K2 = self.K1, self.K2
        D = self.feat_dim

        x_self = np.zeros((B, D), dtype=np.float32)
        x_n1 = np.zeros((B, K1, D), dtype=np.float32)
        et_n1 = np.zeros((B, K1), dtype=np.int64)
        mask_n1 = np.zeros((B, K1), dtype=np.float32)
        x_n2 = np.zeros((B, K1, K2, D), dtype=np.float32)
        et_n2 = np.zeros((B, K1, K2), dtype=np.int64)
        mask_n2 = np.zeros((B, K1, K2), dtype=np.float32)

        zero_feat = np.zeros(D, dtype=np.float32)

        for i, nid in enumerate(node_ids):
            x_self[i] = self.features.get(nid, zero_feat)

            # 1-hop sampling
            n1_ids, n1_ets, n1_mask = self._sample_neighbors(nid, K1)
            et_n1[i] = n1_ets
            mask_n1[i] = np.array(n1_mask, dtype=np.float32)

            for j, nb1 in enumerate(n1_ids):
                x_n1[i, j] = self.features.get(nb1, zero_feat)

                # 2-hop sampling
                n2_ids, n2_ets, n2_mask = self._sample_neighbors(nb1, K2)
                et_n2[i, j] = n2_ets
                mask_n2[i, j] = np.array(n2_mask, dtype=np.float32)

                for k, nb2 in enumerate(n2_ids):
                    x_n2[i, j, k] = self.features.get(nb2, zero_feat)

        return {
            "x_self": torch.from_numpy(x_self),
            "x_n1": torch.from_numpy(x_n1),
            "et_n1": torch.from_numpy(et_n1),
            "mask_n1": torch.from_numpy(mask_n1),
            "x_n2": torch.from_numpy(x_n2),
            "et_n2": torch.from_numpy(et_n2),
            "mask_n2": torch.from_numpy(mask_n2),
        }


# ═══════════════════════════════════════════════════════════════════════════
# TRAINING LOOP
# ═══════════════════════════════════════════════════════════════════════════

def train(
    num_benign: int = 10_000,
    epochs: int = 30,
    batch_size: int = 256,
    lr: float = 1e-3,
    K1: int = 10,
    K2: int = 5,
    device: str = "auto",
):
    if device == "auto":
        device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"Device: {device}")

    # ── Step 1: Generate dataset ──────────────────────────────────────────
    print("\n" + "=" * 70)
    print("  Step 1: Generating campaign dataset")
    print("=" * 70)

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
    num_malicious = int(labels.sum())
    print(f"Total nodes: {total_nodes:,} | Malicious: {num_malicious:,} ({num_malicious/total_nodes:.2%})")

    # ── Step 2: Build node features ──────────────────────────────────────
    print("\n" + "=" * 70)
    print("  Step 2: Building node features")
    print("=" * 70)

    rng = np.random.default_rng(42)
    t0 = time.perf_counter()
    node_features = build_node_features(node_metadata, all_node_ids, rng)
    print(f"Built {len(node_features):,} feature vectors in {time.perf_counter()-t0:.2f}s")

    # ── Step 3: Train/test split ─────────────────────────────────────────
    print("\n" + "=" * 70)
    print("  Step 3: Train/test split")
    print("=" * 70)

    train_ids, test_ids, y_train, y_test = campaign_disjoint_split(
        all_node_ids,
        labels,
        campaign_info,
        test_size=0.2,
        random_state=42,
    )
    n_train_inst = sum(1 for i, c in enumerate(campaign_info) if int(c["nodes"][0]) in set(train_ids.tolist()))
    n_test_inst = len(campaign_info) - n_train_inst
    print(f"Train: {len(train_ids):,} ({y_train.sum():,} malicious from {n_train_inst} campaigns)")
    print(f"Test:  {len(test_ids):,} ({y_test.sum():,} malicious from {n_test_inst} campaigns)")

    # ── Step 4: Initialize sampler and models ────────────────────────────
    print("\n" + "=" * 70)
    print("  Step 4: Initializing models")
    print("=" * 70)

    sampler = NeighborSampler(
        adj_list=adj_list,
        edge_types_map=edge_types_map,
        node_features=node_features,
        K1=K1,
        K2=K2,
        seed=42,
    )

    gnn = FragGNN(node_feat_dim=NODE_FEAT_DIM, hidden_dim=256, embed_dim=128).to(device)
    scorer = FragScorer(embed_dim=128, hidden=64).to(device)

    total_params = sum(p.numel() for p in gnn.parameters()) + sum(p.numel() for p in scorer.parameters())
    print(f"FragGNN params:   {sum(p.numel() for p in gnn.parameters()):,}")
    print(f"FragScorer params: {sum(p.numel() for p in scorer.parameters()):,}")
    print(f"Total params:     {total_params:,}")

    # Class-weighted BCE to handle imbalance
    pos_weight = torch.tensor([(y_train == 0).sum() / max((y_train == 1).sum(), 1)],
                               dtype=torch.float32).to(device)
    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    print(f"Pos weight: {pos_weight.item():.1f} (accounts for class imbalance)")

    optimizer = torch.optim.Adam(
        list(gnn.parameters()) + list(scorer.parameters()),
        lr=lr,
        weight_decay=1e-5,
    )
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)

    # ── Step 5: Training ─────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("  Step 5: Training GNN + Scorer")
    print("=" * 70)

    best_auc = 0.0
    best_state = None

    for epoch in range(epochs):
        gnn.train()
        scorer.train()

        # Shuffle training nodes
        perm = rng.permutation(len(train_ids))
        train_ids_shuffled = train_ids[perm]
        y_train_shuffled = y_train[perm]

        epoch_loss = 0.0
        n_batches = 0

        for start in range(0, len(train_ids_shuffled), batch_size):
            end = min(start + batch_size, len(train_ids_shuffled))
            batch_nodes = train_ids_shuffled[start:end]
            batch_labels = torch.from_numpy(
                y_train_shuffled[start:end].astype(np.float32)
            ).to(device)

            # Sample neighborhoods
            batch = sampler.sample_batch(batch_nodes)
            batch = {k: v.to(device) for k, v in batch.items()}

            # Forward pass: GNN → embeddings → scorer → logits
            embeddings = gnn(
                x_self=batch["x_self"],
                x_n1=batch["x_n1"],
                et_n1=batch["et_n1"],
                mask_n1=batch["mask_n1"],
                x_n2=batch["x_n2"],
                et_n2=batch["et_n2"],
                mask_n2=batch["mask_n2"],
            )
            logits = scorer(embeddings)
            loss = criterion(logits, batch_labels)

            optimizer.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(
                list(gnn.parameters()) + list(scorer.parameters()), max_norm=1.0
            )
            optimizer.step()

            epoch_loss += loss.item()
            n_batches += 1

        scheduler.step()
        avg_loss = epoch_loss / max(n_batches, 1)

        # ── Evaluate every 5 epochs ──────────────────────────────────────
        if (epoch + 1) % 5 == 0 or epoch == 0:
            gnn.eval()
            scorer.eval()
            all_probs = []
            all_labels = []

            with torch.no_grad():
                for start in range(0, len(test_ids), batch_size):
                    end = min(start + batch_size, len(test_ids))
                    batch_nodes = test_ids[start:end]
                    batch_labels_np = y_test[start:end]

                    batch = sampler.sample_batch(batch_nodes)
                    batch = {k: v.to(device) for k, v in batch.items()}

                    embeddings = gnn(
                        x_self=batch["x_self"],
                        x_n1=batch["x_n1"],
                        et_n1=batch["et_n1"],
                        mask_n1=batch["mask_n1"],
                        x_n2=batch["x_n2"],
                        et_n2=batch["et_n2"],
                        mask_n2=batch["mask_n2"],
                    )
                    probs = scorer.score(embeddings).cpu().numpy()
                    all_probs.append(probs)
                    all_labels.append(batch_labels_np)

            all_probs = np.concatenate(all_probs)
            all_labels = np.concatenate(all_labels)

            auc = roc_auc_score(all_labels, all_probs)
            ap = average_precision_score(all_labels, all_probs)

            improved = ""
            if auc > best_auc:
                best_auc = auc
                best_state = {
                    "gnn": {k: v.cpu().clone() for k, v in gnn.state_dict().items()},
                    "scorer": {k: v.cpu().clone() for k, v in scorer.state_dict().items()},
                }
                improved = " *best*"

            print(f"  Epoch {epoch+1:>3}/{epochs} | Loss: {avg_loss:.4f} | "
                  f"AUC: {auc:.4f} | AP: {ap:.4f} | "
                  f"LR: {scheduler.get_last_lr()[0]:.6f}{improved}")
        else:
            print(f"  Epoch {epoch+1:>3}/{epochs} | Loss: {avg_loss:.4f} | "
                  f"LR: {scheduler.get_last_lr()[0]:.6f}")

    # ── Step 6: Final evaluation with best model ─────────────────────────
    print("\n" + "=" * 70)
    print("  Step 6: Final Evaluation (best checkpoint)")
    print("=" * 70)

    if best_state is not None:
        gnn.load_state_dict(best_state["gnn"])
        scorer.load_state_dict(best_state["scorer"])

    gnn.eval()
    scorer.eval()
    all_probs = []
    all_labels = []

    t0 = time.perf_counter()
    with torch.no_grad():
        for start in range(0, len(test_ids), batch_size):
            end = min(start + batch_size, len(test_ids))
            batch_nodes = test_ids[start:end]
            batch_labels_np = y_test[start:end]

            batch = sampler.sample_batch(batch_nodes)
            batch = {k: v.to(device) for k, v in batch.items()}

            embeddings = gnn(
                x_self=batch["x_self"],
                x_n1=batch["x_n1"],
                et_n1=batch["et_n1"],
                mask_n1=batch["mask_n1"],
                x_n2=batch["x_n2"],
                et_n2=batch["et_n2"],
                mask_n2=batch["mask_n2"],
            )
            probs = scorer.score(embeddings).cpu().numpy()
            all_probs.append(probs)
            all_labels.append(batch_labels_np)

    infer_time = time.perf_counter() - t0
    all_probs = np.concatenate(all_probs)
    all_labels = np.concatenate(all_labels)

    y_pred = (all_probs > 0.5).astype(int)

    print(f"\n  Inference time: {infer_time:.2f}s for {len(test_ids):,} nodes")
    print(f"  Per-node: {infer_time/len(test_ids)*1e6:.1f} µs")

    auc = roc_auc_score(all_labels, all_probs)
    ap = average_precision_score(all_labels, all_probs)
    print(f"\n  ROC AUC:           {auc:.4f}")
    print(f"  Average Precision: {ap:.4f}")

    print(f"\n  Classification Report:")
    print(classification_report(all_labels, y_pred,
                                 target_names=["benign", "malicious"],
                                 digits=4))

    cm = confusion_matrix(all_labels, y_pred)
    tn, fp, fn, tp = cm.ravel()
    print(f"  Confusion Matrix:")
    print(f"    True Negatives:  {tn:>6,}  (benign correctly classified)")
    print(f"    False Positives: {fp:>6,}  (benign flagged as malicious)")
    print(f"    False Negatives: {fn:>6,}  (malicious missed)")
    print(f"    True Positives:  {tp:>6,}  (malicious caught)")

    # ── Save model ───────────────────────────────────────────────────────
    save_dir = os.path.join(os.path.dirname(__file__), "..", "checkpoints")
    os.makedirs(save_dir, exist_ok=True)
    save_path = os.path.join(save_dir, "fragguard_gnn.pt")

    torch.save({
        "gnn_state_dict": gnn.state_dict(),
        "scorer_state_dict": scorer.state_dict(),
        "config": {
            "node_feat_dim": NODE_FEAT_DIM,
            "hidden_dim": 256,
            "embed_dim": 128,
            "K1": K1,
            "K2": K2,
        },
        "metrics": {
            "roc_auc": auc,
            "avg_precision": ap,
            "best_val_auc": best_auc,
        },
    }, save_path)
    print(f"\n  Model saved to: {save_path}")

    return gnn, scorer, auc


if __name__ == "__main__":
    train(
        num_benign=10_000,
        epochs=30,
        batch_size=256,
        lr=1e-3,
        K1=10,
        K2=5,
    )
