"""
Serving microbenchmark.

Measures the hot-path latency of FragGuardServer.score_nodes by
bypassing RocksDB and feeding synthetic embeddings directly into the
MLP. This isolates the compute cost from the storage cost so we can
report both numbers honestly.

Expected on a modern CPU (single core, no AVX-512 tricks):
  * MLP-only throughput:   3–8 M nodes/sec  (embed_dim=128, hidden=64)
  * With warm RocksDB:     1–2 M nodes/sec  (lookup dominates)
  * With cold RocksDB:     ~100 K nodes/sec (disk-bound; grow your cache)
"""

from __future__ import annotations

import time

import numpy as np
import torch

from models import FragScorer


def bench_mlp_only(n: int = 1_000_000, embed_dim: int = 128, batch: int = 8192):
    scorer = FragScorer(embed_dim=embed_dim).eval()

    rng = np.random.default_rng(0)
    # Pre-generate the whole pool so we're not timing RNG.
    pool = torch.from_numpy(
        rng.standard_normal((n, embed_dim), dtype=np.float32)
    )

    # Warmup — first call allocates kernels and JIT-compiles nothing in
    # particular but still costs ~1 ms that would skew small runs.
    with torch.inference_mode():
        _ = scorer.score(pool[:batch])

    t0 = time.perf_counter()
    with torch.inference_mode():
        for i in range(0, n, batch):
            _ = scorer.score(pool[i : i + batch])
    dt = time.perf_counter() - t0

    rate = n / dt
    print(f"[mlp ] n={n:,} batch={batch} time={dt*1e3:.1f} ms  "
          f"rate={rate:,.0f} nodes/s  ({dt/n*1e6:.2f} µs/node)")
    return rate


if __name__ == "__main__":
    torch.set_num_threads(1)  # keep it honest; scale with cores in prod
    bench_mlp_only()
