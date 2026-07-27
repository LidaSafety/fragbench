"""
REAL-DATA edge-type ablation (detection-F1 form).

This is the ablation reviewers asked for (AC #2 / zS9F / VL5J), but wired to the
REAL executed traces instead of the synthetic CampaignDatasetGenerator. It
consumes the standard normalized dataset contract emitted by
`dataset/normalize_dataset.py`:

    malicious.json  {is_malicious:true,  malicious_source:[...], sessions:[[[event]]]}
    benign.json     {is_malicious:false,                          sessions:[[[event]]]}

For each edge-type condition it restricts the typed interaction graph to a
subset of edge types (applied identically to the GNN NeighborSampler and the
classical-ML graph-feature engine) and trains the full model panel, then prints
a condition x model F1 table — the same shape as compare_gnns, but on real data
and with edges built by the paper's real Step-2 rules (incl. the previously
unimplemented argument_similarity SimHash edge).

Node features are derived DETERMINISTICALLY from event metadata only (tool ->
capability, argument Shannon entropy / length / non-printable ratio). Nothing
about the malicious/benign LABEL is baked into a feature.

The benign split is produced by a separate collaborator; this harness does not
synthesize it. If benign.json has no sessions, the script builds the real graph,
prints the per-condition edge structure, and then reports that F1 requires both
classes — it does NOT invent negatives or print fabricated numbers.

Run:
    cd PrecomputedMLPGNN
    python real_edge_ablation.py --malicious /path/malicious.json --benign /path/benign.json
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
from collections import defaultdict

import numpy as np
import torch

for _rel in ("..", "../training", "../PrecomputedMLPGNN", "../GradientBoostedTree",
             "../dataset"):
    _p = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), _rel))
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)
from build_real_graph import build_edges  # real Step-2 typed edges + SimHash

from train_gnn import NeighborSampler, build_node_features, campaign_disjoint_split
from compare_gnns import train_single_arch, train_ml_methods, ARCH_DISPLAY


EDGE_NAMES = ["data_flow", "temporal", "shared_resource", "shared_session", "argument_similarity"]
WITHIN = {0, 1, 3}
CROSS = {2, 4}
ALL = {0, 1, 2, 3, 4}
CONDITIONS = {
    "full": ALL,
    "within_session_only": WITHIN,
    "cross_session_only": CROSS,
    "drop_shared_resource": ALL - {2},
    "drop_argument_similarity": ALL - {4},
    "no_edges": set(),
}

# Real MCP toolkit tool -> capability category (metadata, not label).
TOOL_CAP = {
    "read_file": "file_read", "read_file_bytes": "file_read", "list_directory": "file_read",
    "glob_files": "file_read", "search_in_files": "file_read", "file_info": "file_read",
    "copy_path": "file_read",
    "write_file": "file_write", "append_file": "file_write", "edit_file": "file_write",
    "create_directory": "file_write", "delete_path": "file_write", "move_path": "file_write",
    "change_permissions": "file_write", "stage_paths": "file_write",
    "synthesize_command": "process_exec", "run_command": "process_exec",
    "create_archive": "crypto",
    "plan_exfil": "network_outbound", "upload_archive": "network_outbound",
    "scan_subnet": "recon", "summarize_exposure": "recon",
}


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = defaultdict(int)
    for ch in s:
        counts[ch] += 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _nonprintable_ratio(s: str) -> float:
    if not s:
        return 0.0
    npc = sum(1 for ch in s if ord(ch) < 32 or ord(ch) > 126)
    return npc / len(s)


def _flatten(payload, is_mal, nodes, sessions, campaign_groups, group_key_fn):
    """Append tool_call events from a normalized payload as graph nodes."""
    src = payload.get("malicious_source") or []
    for vi, variation in enumerate(payload.get("sessions", [])):
        gkey = group_key_fn(src, vi, is_mal)
        for fragment in variation:
            for ev in fragment:
                if ev.get("event") != "tool_call":
                    continue
                args = ev.get("arguments")
                if not isinstance(args, str):
                    args = json.dumps(args, sort_keys=True) if args is not None else ""
                sid = ev.get("session_id") or f"{'mal' if is_mal else 'ben'}_v{vi}"
                nid = len(nodes)
                nodes.append({"id": nid, "session_id": sid, "arguments": args,
                              "tool": ev.get("tool"), "label": 1 if is_mal else 0})
                sessions[sid].append(nid)
                if is_mal:
                    campaign_groups[gkey].append(nid)
    return nodes, sessions, campaign_groups


def load_dataset(mal_path, ben_path):
    nodes, sessions, groups = [], defaultdict(list), defaultdict(list)

    def mal_key(src, vi, is_mal):
        # group by campaign FAMILY (e.g. DEEPFAKE_ID_FRAUD), not the per-variation
        # campaign_id, so no campaign family straddles the train/test split.
        if vi < len(src):
            fam = src[vi].get("campaign") or src[vi].get("campaign_id")
            if fam:
                return fam
        return f"malvar_{vi}"

    mal = json.load(open(mal_path)) if mal_path and os.path.exists(mal_path) else {"sessions": []}
    _flatten(mal, True, nodes, sessions, groups, mal_key)
    ben = json.load(open(ben_path)) if ben_path and os.path.exists(ben_path) else {"sessions": []}
    _flatten(ben, False, nodes, sessions, groups, mal_key)

    labels = np.array([n["label"] for n in nodes], dtype=np.int64)
    # node_metadata for build_node_features (features from event metadata only)
    node_metadata = {}
    for n in nodes:
        cap = TOOL_CAP.get(n["tool"])
        args = n["arguments"]
        node_metadata[n["id"]] = {
            "capabilities": {cap} if cap else set(),
            "api_calls": {n["tool"]} if n["tool"] else set(),
            "string_entropy": _entropy(args),
            "obfuscation_score": _nonprintable_ratio(args),
            "code_complexity": min(len(args) / 200.0, 30.0),
            "risk_score": 0.1,  # neutral; NOT set from label
        }
    campaign_info = [{"nodes": v} for v in groups.values()]
    return nodes, sessions, labels, node_metadata, campaign_info


def _edge_count(adj):
    return sum(len(v) for v in adj.values())


def to_adj(edges_by_type, keep):
    """Build adj_list + edge_types_map (compare_gnns/NeighborSampler format)."""
    adj = defaultdict(list)
    etm = {}
    for t in keep:
        for i, j in edges_by_type[t]:
            adj[i].append(j)
            adj[j].append(i)
            etm[(i, j)] = t
            etm[(j, i)] = t
    return dict(adj), etm


def run(mal_path, ben_path, epochs, num_benign_note=True, seed=42):
    device = "cuda" if torch.cuda.is_available() else "cpu"
    print("=" * 100)
    print("  FragBench Defense — REAL-DATA Edge-Type Ablation")
    print("=" * 100)
    nodes, sessions, labels, node_metadata, campaign_info = load_dataset(mal_path, ben_path)
    n = len(nodes)
    n_mal = int(labels.sum())
    n_ben = n - n_mal
    print(f"  nodes: {n:,}  (malicious {n_mal:,} / benign {n_ben:,})   "
          f"sessions: {len(sessions):,}   malicious campaign-instances: {len(campaign_info)}")

    print("  Building real typed edges (paper Step 2 + argument_similarity SimHash) ...")
    edges = build_edges(nodes, sessions)
    for t in range(5):
        print(f"    {EDGE_NAMES[t]:<20s} {len(edges[t]):>9,}")

    if n_ben == 0:
        print("\n  " + "!" * 90)
        print("  benign.json has 0 sessions -> only one class present.")
        print("  F1/AUC are undefined without negatives, so NO detection numbers are")
        print("  produced here (this harness never fabricates a benign class).")
        print("  Per-condition REAL edge structure that the ablation WILL train on:")
        print("  " + "-" * 90)
        print(f"    {'condition':<24s}{'kept edge types':>44s}{'edges':>12s}")
        for cond, keep in CONDITIONS.items():
            names = ",".join(EDGE_NAMES[i] for i in sorted(keep)) or "(none)"
            tot = sum(len(edges[t]) for t in keep)
            print(f"    {cond:<24s}{names:>44s}{tot:>12,}")
        print("\n  Drop a real benign.json (same normalized schema) next to malicious.json")
        print("  and re-run — the full condition x model F1 table prints automatically.")
        return

    # ── both classes present: run the real F1 ablation ────────────────────────
    all_ids = list(range(n))
    rng = np.random.default_rng(seed)
    node_features = build_node_features(node_metadata, all_ids, rng)
    train_ids, test_ids, y_train, y_test = campaign_disjoint_split(
        all_ids, labels, campaign_info, test_size=0.2, random_state=seed)
    print(f"  Split: train {len(train_ids):,} ({int(y_train.sum())} mal) | "
          f"test {len(test_ids):,} ({int(y_test.sum())} mal)")

    import gc
    out = os.path.join(os.path.dirname(__file__), "..", "checkpoints", "real_edge_ablation.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)

    architectures = ["sage", "gat", "gcn", "gin"]
    table = {}
    for cond, keep in CONDITIONS.items():
        adj, etm = to_adj(edges, keep)
        print("\n" + "-" * 100)
        print(f"  CONDITION: {cond}  |  edges: {_edge_count(adj):,}", flush=True)
        sampler = NeighborSampler(adj, etm, node_features, K1=10, K2=5, seed=seed)
        row = {}
        for arch in architectures:
            m = train_single_arch(arch=arch, sampler=sampler,
                                  train_ids=train_ids, y_train=y_train,
                                  test_ids=test_ids, y_test=y_test,
                                  epochs=epochs, batch_size=256, lr=1e-3, device=device)
            row[arch] = m["f1"]
            print(f"    {ARCH_DISPLAY[arch]:<12s} F1={m['f1']:.4f}", flush=True)
        try:
            for r in train_ml_methods(adj_list=adj, node_metadata=node_metadata, edge_types_map=etm,
                                      train_ids=train_ids, y_train=y_train,
                                      test_ids=test_ids, y_test=y_test):
                row[r["arch"]] = r["f1"]
                print(f"    {ARCH_DISPLAY.get(r['arch'], r['arch']):<12s} F1={r['f1']:.4f}", flush=True)
        except Exception as e:  # keep GNN results even if the ML panel fails
            print(f"    [ML panel skipped for {cond}: {type(e).__name__}: {e}]", flush=True)
        table[cond] = row
        # persist after every condition so an OOM can't wipe completed work
        json.dump({"conditions": table, "note": "real-data campaign-disjoint"},
                  open(out, "w"), indent=2)
        del adj, etm, sampler
        gc.collect()

    model_keys = architectures + [k for k in table["full"] if k not in architectures]
    print("\n" + "=" * 100)
    print("  REAL-DATA EDGE-TYPE ABLATION — aggregate F1")
    print("=" * 100)
    header = f"  {'condition':<22s}" + "".join(f"{ARCH_DISPLAY.get(k, k)[:9]:>10s}" for k in model_keys)
    print(header)
    print("  " + "-" * (len(header) - 2))
    for cond in CONDITIONS:
        print(f"  {cond:<22s}" + "".join(f"{table[cond].get(k, float('nan')):>10.3f}" for k in model_keys))

    out = os.path.join(os.path.dirname(__file__), "..", "checkpoints", "real_edge_ablation.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump({"conditions": table, "model_keys": model_keys}, open(out, "w"), indent=2)
    print(f"\n  Saved: {out}")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--malicious", required=True)
    p.add_argument("--benign", default=None)
    p.add_argument("--epochs", type=int, default=30)
    args = p.parse_args()
    run(args.malicious, args.benign, args.epochs)
