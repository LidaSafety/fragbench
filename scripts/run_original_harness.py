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
    ap.add_argument("--test-size", type=float, default=0.3,
                    help="outer-sample holdout fraction; Table 3 reports 70/30 "
                         "but the harness hardcodes 0.2 (default: 0.3)")
    ap.add_argument("--out", help="where to move the harness' results file "
                                  "(default: results_harness_<benign stem>.json)")
    args = ap.parse_args()

    # compare_gnns.py writes checkpoints/gnn_comparison.json, a fixed path with
    # no parameter, so a second arm would silently overwrite the first. Claim a
    # distinct destination up front and check the run is not already racing one.
    checkpoint = (REPO / "fragbench-structural-graph-main" / "checkpoints"
                  / ("gnn_comparison.json" if args.script == "compare_gnns"
                     else "fragguard_gnn.pt"))
    out = Path(args.out) if args.out else REPO / (
        f"results_harness_{Path(args.benign).stem}.json")
    if out.exists():
        print(f"refusing to overwrite {out} -- move it or pass --out", file=sys.stderr)
        return 2

    prepare(args.malicious, args.benign,
            args.malicious_sample, args.benign_sample, args.seed)

    import importlib
    mod = importlib.import_module(args.script)
    mod.CampaignDatasetGenerator = TraceDatasetGenerator   # the only substitution

    # compare_gnns.py:614 and train_gnn.py:311 both hardcode test_size=0.2, but
    # Table 3 reports a 70/30 outer-sample split. main() takes no test_size
    # argument, so force the ratio by wrapping the splitter in the module's
    # namespace. Pass --test-size 0.2 to reproduce the harness default instead.
    if args.test_size is not None:
        inner = mod.campaign_disjoint_split

        def split(all_node_ids, labels, campaign_info, test_size=0.2,
                  random_state=42, _inner=inner, _ts=args.test_size):
            return _inner(all_node_ids, labels, campaign_info,
                          test_size=_ts, random_state=random_state)

        mod.campaign_disjoint_split = split
        print(f"split: test_size={args.test_size} "
              f"({100*(1-args.test_size):.0f}/{100*args.test_size:.0f} outer-sample)")

    print(f"\nrunning {args.script}.{'main' if args.script == 'compare_gnns' else 'train'}() "
          f"unmodified on the trace graph\n")
    if args.script == "compare_gnns":
        mod.main(epochs=args.epochs, batch_size=args.batch_size)
    else:
        mod.train(epochs=args.epochs, batch_size=args.batch_size)

    if checkpoint.exists():
        checkpoint.rename(out)
        print(f"\nresults moved to {out}")
        print("  (the harness writes one fixed filename, so each arm is "
              "claimed here rather than left to be overwritten)")
    else:
        print(f"\nwarning: expected {checkpoint} but it was not written",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
