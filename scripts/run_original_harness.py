#!/usr/bin/env python3
"""Run training/compare_gnns.py verbatim, with traces substituted for synthetic data.

compare_gnns.main() and train_gnn.train() both construct their dataset inline:

    gen = CampaignDatasetGenerator(seed=42)
    adj_list, node_metadata, edge_types_map, labels, campaign_info = gen.generate(...)

There is no parameter for supplying a graph, so running either script unchanged
re-runs the synthetic benchmark. This module replaces *only that one object* in
the target module's namespace with a stub whose .generate() returns a graph built
from the real MCP traces. Everything downstream -- the split, node features,
neighbour sampling, all four GNNs, all seven classical baselines, the reporting --
is the original code path, executed line for line.

    python scripts/run_original_harness.py --benign dataset/combined/benign.json
    python scripts/run_original_harness.py --benign benign_executed.json
    python scripts/run_original_harness.py --script train_gnn --epochs 30
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "fragbench-structural-graph-main" / "training"))
sys.path.insert(0, str(REPO / "scripts"))

from train_on_traces import build_graph, load  # noqa: E402


class TraceDatasetGenerator:
    """Drop-in stand-in for CampaignDatasetGenerator backed by real traces.

    Same constructor and same generate() return signature, so the calling code
    cannot tell the difference. Every keyword the original accepts is swallowed
    and ignored -- the graph is fixed by the corpora, not by generator knobs.
    """

    graph = None   # set by prepare() before the harness runs

    def __init__(self, seed: int = 42):
        self.seed = seed

    def generate(self, *args, **kwargs):
        if TraceDatasetGenerator.graph is None:
            raise RuntimeError("call prepare() before running the harness")
        return TraceDatasetGenerator.graph


def prepare(malicious: str, benign: str, mal_sample, ben_sample, seed: int):
    """Build the trace graph in the 5-tuple shape gen.generate() returns."""
    print("building the fragment graph from traces")
    corpus = load(malicious, 1, mal_sample, seed) + load(benign, 0, ben_sample, seed)
    adj, meta, etypes, labels, sample_of, _camp = build_graph(corpus)

    # campaign_info: one entry per malicious outer sample, which is what
    # campaign_disjoint_split holds out wholesale.
    nid = np.arange(len(labels))
    campaign_info = [
        {"nodes": nid[(sample_of == s) & (labels == 1)].tolist()}
        for s in sorted(set(sample_of[labels == 1].tolist()))
    ]
    print(f"  nodes={len(labels):,}  edges={len(etypes):,}  "
          f"malicious={labels.sum():,}  instances={len(campaign_info)}")
    TraceDatasetGenerator.graph = (adj, meta, etypes, labels, campaign_info)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--malicious", default="dataset/combined/malicious.json")
    ap.add_argument("--benign", default="dataset/combined/benign.json")
    ap.add_argument("--malicious-sample", type=int)
    ap.add_argument("--benign-sample", type=int)
    ap.add_argument("--script", choices=("compare_gnns", "train_gnn"),
                    default="compare_gnns")
    ap.add_argument("--epochs", type=int, default=30)
    ap.add_argument("--batch-size", type=int, default=256)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    prepare(args.malicious, args.benign,
            args.malicious_sample, args.benign_sample, args.seed)

    import importlib
    mod = importlib.import_module(args.script)
    mod.CampaignDatasetGenerator = TraceDatasetGenerator   # the only substitution

    print(f"\nrunning {args.script}.{'main' if args.script == 'compare_gnns' else 'train'}() "
          f"unmodified on the trace graph\n")
    if args.script == "compare_gnns":
        mod.main(epochs=args.epochs, batch_size=args.batch_size)
    else:
        mod.train(epochs=args.epochs, batch_size=args.batch_size)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
