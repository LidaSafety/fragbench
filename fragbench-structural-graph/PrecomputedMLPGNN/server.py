"""
Online scoring service.

Hot path per node:
  1. KV lookup by node_id   (dominant cost, ~700 ns with a warm cache)
  2. fp16 -> fp32 unpack
  3. 2-layer MLP            (~200 ns on CPU for embed_dim=128, hidden=64)
  4. sigmoid + threshold

Everything is batched. The MLP is eager-mode PyTorch on CPU — at this
size TorchScript/ONNX don't meaningfully beat it, and staying in Python
keeps the ops team happy. For GPU serving, flip `device` and expect
multi-million nodes/sec per card.

The staleness check compares the embedding's version header against
`current_version`. Stale embeddings are *not* treated as errors — we
still score them, but we return a `stale=True` flag so the caller can
decide whether to trigger a synchronous re-embed for that node. In
practice the policy is: stale + score > 0.3 -> re-embed; otherwise
accept the cached answer.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Sequence

import numpy as np
import torch

from embedder import EMBED_HEADER
from models import FragScorer


@dataclass
class ScoreResult:
    node_id: int
    score: float          # P(malicious) in [0, 1]
    stale: bool           # True if embedding is from an older refresh
    missing: bool = False # True if the node wasn't in the KV store


class FragGuardServer:
    def __init__(
        self,
        db_path: str,
        scorer_state: dict,
        embed_dim: int = 128,
        current_version: int = 1,
        threshold: float = 0.5,
        device: str = "cpu",
    ):
        import rocksdb

        opts = rocksdb.Options(create_if_missing=False)
        # Read-optimized: bigger block cache, no write buffers needed.
        opts.block_cache = rocksdb.LRUCache(capacity=8 * 1024 * 1024 * 1024)
        self.db = rocksdb.DB(db_path, opts, read_only=True)

        self.scorer = FragScorer(embed_dim=embed_dim)
        self.scorer.load_state_dict(scorer_state)
        self.scorer.eval().to(device)

        self.embed_dim = embed_dim
        self.current_version = current_version
        self.threshold = threshold
        self.device = device

        self._val_stride = 2 * embed_dim  # fp16 body
        self._hdr_size = EMBED_HEADER.size

    # ------------------------------------------------------------------
    # Batched entry point. This is what the gateway calls per request —
    # one request can carry many fragments (a single user session often
    # produces 10-100 nodes), so batching here is the whole ball game.
    # ------------------------------------------------------------------
    def score_nodes(self, node_ids: Sequence[int]) -> list[ScoreResult]:
        if not node_ids:
            return []

        # 1. Batch multiget from RocksDB. Keys are big-endian uint64.
        keys = [int(n).to_bytes(8, "big") for n in node_ids]
        raw = self.db.multi_get(keys)  # dict {key: bytes|None}

        # 2. Decode into one dense array; track which rows were missing.
        n = len(node_ids)
        buf = np.zeros((n, self.embed_dim), dtype=np.float16)
        missing = np.zeros(n, dtype=bool)
        stale = np.zeros(n, dtype=bool)

        for i, k in enumerate(keys):
            v = raw.get(k)
            if v is None or len(v) != self._hdr_size + self._val_stride:
                missing[i] = True
                continue
            version = EMBED_HEADER.unpack_from(v, 0)[0]
            if version != self.current_version:
                stale[i] = True
            body = v[self._hdr_size :]
            buf[i] = np.frombuffer(body, dtype=np.float16)

        # 3. Score everything in one shot. Missing rows get zero vectors,
        #    which the MLP happens to score near its prior — we override
        #    to 0.0 below rather than trusting that.
        z = torch.from_numpy(buf.astype(np.float32)).to(self.device)
        with torch.inference_mode():
            probs = self.scorer.score(z).cpu().numpy()

        results: list[ScoreResult] = []
        for i, nid in enumerate(node_ids):
            if missing[i]:
                results.append(ScoreResult(nid, 0.0, stale=False, missing=True))
            else:
                results.append(
                    ScoreResult(nid, float(probs[i]), stale=bool(stale[i]))
                )
        return results

    def is_malicious(self, node_id: int) -> bool:
        r = self.score_nodes([node_id])[0]
        return (not r.missing) and r.score >= self.threshold

    # Convenience for the "distributed attack chain" use case: given a
    # set of fragments observed across sessions, return the aggregate
    # score. Uses noisy-OR because fragments are conditionally
    # independent evidence once you condition on the embedding — summing
    # logits would double-count overlap.
    def score_chain(self, node_ids: Sequence[int]) -> float:
        results = self.score_nodes(node_ids)
        p_benign = 1.0
        for r in results:
            if r.missing:
                continue
            p_benign *= (1.0 - r.score)
        return 1.0 - p_benign
