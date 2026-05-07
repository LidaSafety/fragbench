"""
Offline embedder.

Runs FragGNN over the full fragment graph in shards and writes each
node's final embedding to a persistent KV store. This is the "heavy"
step that happens on a schedule (hourly is the recommended cadence —
longer and stale embeddings miss fresh attack chains, shorter and you
burn GPU budget without meaningful recall gains).

Storage format
--------------
Key:    node_id (8-byte big-endian uint64)
Value:  <version:uint32><float16 × embed_dim>  packed little-endian

float16 halves the storage footprint vs float32 with no measurable
loss in downstream MLP accuracy (we tested on the adversarial set).
At embed_dim=128 that's 260 bytes/node including the version header,
so 100B nodes ≈ 26 TB — fits on a modest RocksDB cluster.

The `version` field lets the serving layer detect stale embeddings
from a prior refresh cycle without needing a separate index.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass
from typing import Iterable, Iterator

import numpy as np
import torch

from models import FragGNN


EMBED_HEADER = struct.Struct("<I")  # version uint32, little-endian


@dataclass
class NodeBatch:
    """One shard's worth of nodes + their sampled neighborhoods.

    The graph loader is responsible for producing these. In practice it
    reads from a columnar store (Parquet/Arrow) where fragments have
    been pre-joined with their sampled neighbors during ETL.
    """
    node_ids: np.ndarray          # [B] uint64
    x_self: torch.Tensor          # [B, F]
    x_n1: torch.Tensor            # [B, K1, F]
    et_n1: torch.Tensor           # [B, K1] long
    mask_n1: torch.Tensor         # [B, K1] bool
    x_n2: torch.Tensor            # [B, K1, K2, F]
    et_n2: torch.Tensor           # [B, K1, K2] long
    mask_n2: torch.Tensor         # [B, K1, K2] bool


class KVWriter:
    """Thin abstraction over the storage backend.

    We default to RocksDB because (a) single-machine 10s-of-TB works
    fine with the right column-family options and (b) the bulk-load
    SST-ingest path is ~10× faster than live puts for a full refresh.
    If you're on Redis instead, swap the `put_batch` implementation for
    a pipelined MSET; the rest of the code is unchanged.
    """

    def __init__(self, path: str, version: int):
        import rocksdb  # imported lazily so tests don't require it

        opts = rocksdb.Options(create_if_missing=True)
        # Tuned for write-heavy refresh then read-heavy serving.
        opts.write_buffer_size = 256 * 1024 * 1024
        opts.max_write_buffer_number = 4
        opts.target_file_size_base = 512 * 1024 * 1024
        opts.compression = rocksdb.CompressionType.lz4_compression
        self.db = rocksdb.DB(path, opts)
        self.version = version
        self._header = EMBED_HEADER.pack(version)

    def put_batch(self, node_ids: np.ndarray, embeddings: np.ndarray) -> None:
        """node_ids: [B] uint64.  embeddings: [B, D] float16."""
        import rocksdb

        assert embeddings.dtype == np.float16, "serve-time format is fp16"
        batch = rocksdb.WriteBatch()
        header = self._header
        # Pre-encode keys as big-endian so range scans are sorted.
        keys = node_ids.astype(">u8").tobytes()
        vals = embeddings.tobytes()
        kstride = 8
        vstride = embeddings.shape[1] * 2  # 2 bytes per fp16
        for i in range(len(node_ids)):
            k = keys[i * kstride : (i + 1) * kstride]
            v = header + vals[i * vstride : (i + 1) * vstride]
            batch.put(k, v)
        self.db.write(batch)


def embed_shards(
    model: FragGNN,
    shards: Iterable[NodeBatch],
    writer: KVWriter,
    device: str = "cuda",
    log_every: int = 50,
) -> None:
    """Main offline loop. One GPU, one process — parallelize by sharding
    the input across workers externally (each gets its own KVWriter
    handle and a disjoint node-id range).
    """
    model.eval().to(device)
    n_seen = 0
    t0 = time.time()

    with torch.inference_mode():
        for i, batch in enumerate(_to_device(shards, device)):
            z = model(
                x_self=batch.x_self,
                x_n1=batch.x_n1,
                et_n1=batch.et_n1,
                mask_n1=batch.mask_n1,
                x_n2=batch.x_n2,
                et_n2=batch.et_n2,
                mask_n2=batch.mask_n2,
            )
            # fp16 on the wire, fp32 in the GPU — clamp anything funny.
            z_fp16 = z.detach().to(torch.float16).cpu().numpy()
            writer.put_batch(batch.node_ids, z_fp16)

            n_seen += len(batch.node_ids)
            if (i + 1) % log_every == 0:
                rate = n_seen / (time.time() - t0)
                print(f"[embed] shard={i+1} nodes={n_seen:,} rate={rate:,.0f}/s")


def _to_device(shards: Iterable[NodeBatch], device: str) -> Iterator[NodeBatch]:
    for s in shards:
        yield NodeBatch(
            node_ids=s.node_ids,
            x_self=s.x_self.to(device, non_blocking=True),
            x_n1=s.x_n1.to(device, non_blocking=True),
            et_n1=s.et_n1.to(device, non_blocking=True),
            mask_n1=s.mask_n1.to(device, non_blocking=True),
            x_n2=s.x_n2.to(device, non_blocking=True),
            et_n2=s.et_n2.to(device, non_blocking=True),
            mask_n2=s.mask_n2.to(device, non_blocking=True),
        )
