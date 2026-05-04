"""
Inference benchmark for FragGuard GNN pipeline.

Measures latency and throughput at every stage:
  1. MLP-only (FragScorer) — cached embeddings → P(malicious)
  2. GNN-only (FragGNN)   — neighbor-sampled batch → embeddings
  3. End-to-end (GNN + MLP) — raw graph → P(malicious)
  4. Neighbor sampling     — graph traversal to build batches

Each benchmark reports:
  - Total wall time
  - Per-node latency (µs)
  - Throughput (nodes/sec)
  - Percentile latencies (p50, p90, p95, p99)

Usage:
    cd PrecomputedMLPGNN
    python bench_inference.py
"""

from __future__ import annotations

import os
import sys
import time
import statistics

import numpy as np
import torch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "GradientBoostedTree"))

from models import FragGNN, FragScorer, NUM_EDGE_TYPES
from train_gnn import (
    NeighborSampler,
    build_node_features,
    NODE_FEAT_DIM,
)
from main import CampaignDatasetGenerator


# ═══════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def percentiles(latencies_us: list[float]) -> dict:
    latencies_us.sort()
    n = len(latencies_us)
    return {
        "p50": latencies_us[int(n * 0.50)],
        "p90": latencies_us[int(n * 0.90)],
        "p95": latencies_us[int(n * 0.95)],
        "p99": latencies_us[min(int(n * 0.99), n - 1)],
    }


def print_header(title: str):
    print(f"\n{'━' * 70}")
    print(f"  {title}")
    print(f"{'━' * 70}")


def print_results(label: str, total_s: float, n_nodes: int,
                  per_batch_us: list[float] | None = None,
                  batch_size: int = 1):
    per_node_us = total_s / n_nodes * 1e6
    throughput = n_nodes / total_s
    print(f"\n  {label}:")
    print(f"    Total time:   {total_s*1e3:>10.2f} ms")
    print(f"    Nodes scored: {n_nodes:>10,}")
    print(f"    Per-node:     {per_node_us:>10.2f} µs")
    print(f"    Throughput:   {throughput:>10,.0f} nodes/sec")

    if per_batch_us:
        pcts = percentiles(per_batch_us)
        print(f"    Per-batch latency (batch_size={batch_size}):")
        print(f"      p50: {pcts['p50']:>8.1f} µs")
        print(f"      p90: {pcts['p90']:>8.1f} µs")
        print(f"      p95: {pcts['p95']:>8.1f} µs")
        print(f"      p99: {pcts['p99']:>8.1f} µs")


# ═══════════════════════════════════════════════════════════════════════════
# BENCHMARK 1: MLP-only (FragScorer)
# ═══════════════════════════════════════════════════════════════════════════

def bench_mlp(device: str, n: int = 500_000, batch_size: int = 4096,
              embed_dim: int = 128, warmup: int = 10):
    print_header("Benchmark 1: MLP-only (FragScorer)")
    print(f"  Pre-computed embeddings → P(malicious)")
    print(f"  Config: n={n:,} batch={batch_size} embed_dim={embed_dim} device={device}")

    scorer = FragScorer(embed_dim=embed_dim).eval().to(device)
    rng = np.random.default_rng(0)
    pool = torch.from_numpy(
        rng.standard_normal((n, embed_dim)).astype(np.float32)
    ).to(device)

    # Warmup
    with torch.inference_mode():
        for _ in range(warmup):
            _ = scorer.score(pool[:batch_size])
    if device == "cuda":
        torch.cuda.synchronize()

    # Timed run
    batch_latencies = []
    t0 = time.perf_counter()
    with torch.inference_mode():
        for i in range(0, n, batch_size):
            bt0 = time.perf_counter()
            _ = scorer.score(pool[i:i + batch_size])
            if device == "cuda":
                torch.cuda.synchronize()
            batch_latencies.append((time.perf_counter() - bt0) * 1e6)
    total = time.perf_counter() - t0

    print_results("MLP scorer", total, n, batch_latencies, batch_size)
    return total


# ═══════════════════════════════════════════════════════════════════════════
# BENCHMARK 2: GNN-only (FragGNN)
# ═══════════════════════════════════════════════════════════════════════════

def bench_gnn(device: str, n: int = 50_000, batch_size: int = 256,
              K1: int = 10, K2: int = 5, warmup: int = 5):
    print_header("Benchmark 2: GNN-only (FragGNN)")
    print(f"  Pre-sampled neighborhoods → embeddings")
    print(f"  Config: n={n:,} batch={batch_size} K1={K1} K2={K2} device={device}")

    gnn = FragGNN(node_feat_dim=NODE_FEAT_DIM, hidden_dim=256, embed_dim=128).eval().to(device)
    rng = np.random.default_rng(0)

    # Pre-generate synthetic batches (skip sampling cost)
    def make_batch(bs):
        return {
            "x_self": torch.randn(bs, NODE_FEAT_DIM, device=device),
            "x_n1": torch.randn(bs, K1, NODE_FEAT_DIM, device=device),
            "et_n1": torch.randint(0, NUM_EDGE_TYPES, (bs, K1), device=device),
            "mask_n1": torch.ones(bs, K1, device=device),
            "x_n2": torch.randn(bs, K1, K2, NODE_FEAT_DIM, device=device),
            "et_n2": torch.randint(0, NUM_EDGE_TYPES, (bs, K1, K2), device=device),
            "mask_n2": torch.ones(bs, K1, K2, device=device),
        }

    # Warmup
    with torch.inference_mode():
        for _ in range(warmup):
            b = make_batch(batch_size)
            _ = gnn(**b)
    if device == "cuda":
        torch.cuda.synchronize()

    # Timed run
    batch_latencies = []
    scored = 0
    t0 = time.perf_counter()
    with torch.inference_mode():
        for i in range(0, n, batch_size):
            bs = min(batch_size, n - i)
            b = make_batch(bs)
            bt0 = time.perf_counter()
            _ = gnn(**b)
            if device == "cuda":
                torch.cuda.synchronize()
            batch_latencies.append((time.perf_counter() - bt0) * 1e6)
            scored += bs
    total = time.perf_counter() - t0

    print_results("GNN forward", total, scored, batch_latencies, batch_size)
    return total


# ═══════════════════════════════════════════════════════════════════════════
# BENCHMARK 3: End-to-end (sampling + GNN + MLP)
# ═══════════════════════════════════════════════════════════════════════════

def bench_end_to_end(device: str, num_benign: int = 10_000,
                     batch_size: int = 256, K1: int = 10, K2: int = 5,
                     warmup: int = 3):
    print_header("Benchmark 3: End-to-end (sampling + GNN + MLP)")
    print(f"  Raw graph → neighbor sample → GNN → scorer → P(malicious)")
    print(f"  Config: nodes={num_benign:,}+ batch={batch_size} K1={K1} K2={K2} device={device}")

    # Generate dataset
    gen = CampaignDatasetGenerator(seed=42)
    adj_list, node_metadata, edge_types_map, labels, _ = gen.generate(
        num_benign_nodes=num_benign,
        campaigns_to_plant={
            "GTG-1002_espionage": 3,
            "AI_RaaS_developer": 10,
            "PROMPTSTEAL_APT28": 5,
            "ScopeCreep": 8,
            "MalTerminal": 5,
        },
        benign_cross_session_rate=0.15,
        num_sessions=max(1000, num_benign // 10),
        num_users=max(200, num_benign // 50),
    )

    total_nodes = len(labels)
    all_ids = np.arange(total_nodes)
    rng = np.random.default_rng(42)
    node_features = build_node_features(node_metadata, list(range(total_nodes)), rng)

    sampler = NeighborSampler(adj_list, edge_types_map, node_features, K1=K1, K2=K2, seed=42)

    # Load trained model if available, else use random weights
    ckpt_path = os.path.join(os.path.dirname(__file__), "..", "checkpoints", "fragguard_gnn.pt")
    gnn = FragGNN(node_feat_dim=NODE_FEAT_DIM, hidden_dim=256, embed_dim=128).to(device)
    scorer = FragScorer(embed_dim=128, hidden=64).to(device)

    if os.path.exists(ckpt_path):
        ckpt = torch.load(ckpt_path, map_location=device, weights_only=False)
        gnn.load_state_dict(ckpt["gnn_state_dict"])
        scorer.load_state_dict(ckpt["scorer_state_dict"])
        print(f"  Loaded checkpoint: {ckpt_path}")
    else:
        print(f"  No checkpoint found, using random weights")

    gnn.eval()
    scorer.eval()

    # Warmup
    with torch.inference_mode():
        for _ in range(warmup):
            b = sampler.sample_batch(all_ids[:batch_size])
            b = {k: v.to(device) for k, v in b.items()}
            emb = gnn(**b)
            _ = scorer.score(emb)
    if device == "cuda":
        torch.cuda.synchronize()

    # --- 3a: Measure sampling time separately ---
    sampling_latencies = []
    t_sample_start = time.perf_counter()
    for i in range(0, total_nodes, batch_size):
        bt0 = time.perf_counter()
        batch_ids = all_ids[i:i + batch_size]
        _ = sampler.sample_batch(batch_ids)
        sampling_latencies.append((time.perf_counter() - bt0) * 1e6)
    t_sample_total = time.perf_counter() - t_sample_start
    print_results("Neighbor sampling only", t_sample_total, total_nodes,
                  sampling_latencies, batch_size)

    # --- 3b: Measure GNN+MLP (tensors already on device) ---
    gnn_mlp_latencies = []
    t_gnn_start = time.perf_counter()
    with torch.inference_mode():
        for i in range(0, total_nodes, batch_size):
            batch_ids = all_ids[i:i + batch_size]
            b = sampler.sample_batch(batch_ids)
            b = {k: v.to(device) for k, v in b.items()}
            bt0 = time.perf_counter()
            emb = gnn(**b)
            probs = scorer.score(emb)
            if device == "cuda":
                torch.cuda.synchronize()
            gnn_mlp_latencies.append((time.perf_counter() - bt0) * 1e6)
    t_gnn_total = time.perf_counter() - t_gnn_start
    # Subtract approximate sampling time for the compute-only number
    compute_total = sum(l / 1e6 for l in gnn_mlp_latencies)
    print_results("GNN + MLP compute", compute_total, total_nodes,
                  gnn_mlp_latencies, batch_size)

    # --- 3c: Full end-to-end ---
    e2e_latencies = []
    t_e2e_start = time.perf_counter()
    with torch.inference_mode():
        for i in range(0, total_nodes, batch_size):
            bt0 = time.perf_counter()
            batch_ids = all_ids[i:i + batch_size]
            b = sampler.sample_batch(batch_ids)
            b = {k: v.to(device) for k, v in b.items()}
            emb = gnn(**b)
            probs = scorer.score(emb)
            if device == "cuda":
                torch.cuda.synchronize()
            e2e_latencies.append((time.perf_counter() - bt0) * 1e6)
    t_e2e_total = time.perf_counter() - t_e2e_start
    print_results("Full end-to-end", t_e2e_total, total_nodes,
                  e2e_latencies, batch_size)

    return t_e2e_total


# ═══════════════════════════════════════════════════════════════════════════
# BENCHMARK 4: Single-node latency (worst case)
# ═══════════════════════════════════════════════════════════════════════════

def bench_single_node(device: str, n_trials: int = 500, K1: int = 10, K2: int = 5):
    print_header("Benchmark 4: Single-node latency (batch_size=1)")
    print(f"  Simulates real-time per-request scoring")
    print(f"  Config: trials={n_trials} K1={K1} K2={K2} device={device}")

    # Small graph for single-node bench
    gen = CampaignDatasetGenerator(seed=99)
    adj_list, node_metadata, edge_types_map, labels, _ = gen.generate(
        num_benign_nodes=5_000,
        campaigns_to_plant={"ScopeCreep": 5, "MalTerminal": 5},
        benign_cross_session_rate=0.15,
        num_sessions=500,
        num_users=100,
    )
    total_nodes = len(labels)
    rng = np.random.default_rng(99)
    node_features = build_node_features(node_metadata, list(range(total_nodes)), rng)
    sampler = NeighborSampler(adj_list, edge_types_map, node_features, K1=K1, K2=K2, seed=99)

    gnn = FragGNN(node_feat_dim=NODE_FEAT_DIM, hidden_dim=256, embed_dim=128).eval().to(device)
    scorer = FragScorer(embed_dim=128, hidden=64).eval().to(device)

    ckpt_path = os.path.join(os.path.dirname(__file__), "..", "checkpoints", "fragguard_gnn.pt")
    if os.path.exists(ckpt_path):
        ckpt = torch.load(ckpt_path, map_location=device, weights_only=False)
        gnn.load_state_dict(ckpt["gnn_state_dict"])
        scorer.load_state_dict(ckpt["scorer_state_dict"])

    # Warmup
    test_node = np.array([0])
    with torch.inference_mode():
        for _ in range(20):
            b = sampler.sample_batch(test_node)
            b = {k: v.to(device) for k, v in b.items()}
            emb = gnn(**b)
            _ = scorer.score(emb)
    if device == "cuda":
        torch.cuda.synchronize()

    # Measure individual node latencies
    node_ids = rng.integers(0, total_nodes, size=n_trials)
    latencies_sampling = []
    latencies_compute = []
    latencies_total = []

    with torch.inference_mode():
        for nid in node_ids:
            # Sampling
            t0 = time.perf_counter()
            b = sampler.sample_batch(np.array([nid]))
            t_sampled = time.perf_counter()

            # Compute
            b = {k: v.to(device) for k, v in b.items()}
            emb = gnn(**b)
            prob = scorer.score(emb)
            if device == "cuda":
                torch.cuda.synchronize()
            t_done = time.perf_counter()

            latencies_sampling.append((t_sampled - t0) * 1e6)
            latencies_compute.append((t_done - t_sampled) * 1e6)
            latencies_total.append((t_done - t0) * 1e6)

    for name, lats in [("Sampling", latencies_sampling),
                        ("GNN+MLP compute", latencies_compute),
                        ("Total (single node)", latencies_total)]:
        pcts = percentiles(lats.copy())
        mean = statistics.mean(lats)
        print(f"\n  {name}:")
        print(f"    Mean:  {mean:>8.1f} µs")
        print(f"    p50:   {pcts['p50']:>8.1f} µs")
        print(f"    p90:   {pcts['p90']:>8.1f} µs")
        print(f"    p95:   {pcts['p95']:>8.1f} µs")
        print(f"    p99:   {pcts['p99']:>8.1f} µs")


# ═══════════════════════════════════════════════════════════════════════════
# BENCHMARK 5: Batch size sweep
# ═══════════════════════════════════════════════════════════════════════════

def bench_batch_sweep(device: str):
    print_header("Benchmark 5: Batch size sweep (GNN + MLP)")
    print(f"  How throughput scales with batch size")

    gnn = FragGNN(node_feat_dim=NODE_FEAT_DIM, hidden_dim=256, embed_dim=128).eval().to(device)
    scorer = FragScorer(embed_dim=128, hidden=64).eval().to(device)
    K1, K2 = 10, 5

    batch_sizes = [1, 8, 32, 64, 128, 256, 512, 1024, 2048]
    n_repeats = 50

    print(f"\n  {'Batch':>8s}  {'Total ms':>10s}  {'µs/node':>10s}  {'nodes/sec':>12s}")
    print(f"  {'─'*8}  {'─'*10}  {'─'*10}  {'─'*12}")

    for bs in batch_sizes:
        b = {
            "x_self": torch.randn(bs, NODE_FEAT_DIM, device=device),
            "x_n1": torch.randn(bs, K1, NODE_FEAT_DIM, device=device),
            "et_n1": torch.randint(0, NUM_EDGE_TYPES, (bs, K1), device=device),
            "mask_n1": torch.ones(bs, K1, device=device),
            "x_n2": torch.randn(bs, K1, K2, NODE_FEAT_DIM, device=device),
            "et_n2": torch.randint(0, NUM_EDGE_TYPES, (bs, K1, K2), device=device),
            "mask_n2": torch.ones(bs, K1, K2, device=device),
        }

        # Warmup
        with torch.inference_mode():
            for _ in range(10):
                emb = gnn(**b)
                _ = scorer.score(emb)
        if device == "cuda":
            torch.cuda.synchronize()

        # Timed
        t0 = time.perf_counter()
        with torch.inference_mode():
            for _ in range(n_repeats):
                emb = gnn(**b)
                _ = scorer.score(emb)
        if device == "cuda":
            torch.cuda.synchronize()
        dt = time.perf_counter() - t0

        total_nodes = bs * n_repeats
        per_node_us = dt / total_nodes * 1e6
        throughput = total_nodes / dt
        total_ms = dt * 1e3

        print(f"  {bs:>8d}  {total_ms:>10.2f}  {per_node_us:>10.2f}  {throughput:>12,.0f}")


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    print("=" * 70)
    print("  FragGuard GNN Inference Benchmark")
    print("=" * 70)

    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"  Device: {device}")
    if device == "cuda":
        print(f"  GPU: {torch.cuda.get_device_name(0)}")
        print(f"  CUDA: {torch.version.cuda}")
    print(f"  PyTorch: {torch.__version__}")
    print(f"  Threads: {torch.get_num_threads()}")

    # Run all benchmarks
    bench_mlp(device)
    bench_gnn(device)
    bench_end_to_end(device)
    bench_single_node(device)
    bench_batch_sweep(device)

    print(f"\n{'=' * 70}")
    print("  Benchmark complete.")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    main()
