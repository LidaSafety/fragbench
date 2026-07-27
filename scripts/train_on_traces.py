#!/usr/bin/env python3
"""Train the FragBench detectors on real MCP traces.

The training code in fragbench-structural-graph-main/training/ builds its graph
from CampaignDatasetGenerator, a synthetic generator. This script swaps that out
for the normalized trace corpora, keeping the repo's own FragmentFeatureEngine so
the 36 features are computed by unmodified code.

    node   = one tool_call / tool_result event
    edges  = the identity-preserving link-discovery layer (README §1):
               0 data_flow       tool_call_index <-> tool_result_index in a session
               1 temporal        consecutive seq within a session
               2 shared_resource same path / URL / host extracted from arguments
    label  = corpus the event came from

Split is chain-disjoint: every event of a sample lands on one side, so a model
cannot memorise a chain in train and recognise its siblings in test.

Usage
    # rebuttal arm -- executed benign as the control
    python scripts/train_on_traces.py \
        --malicious dataset/combined/malicious.json \
        --benign    benign_executed.json

    # paper arm -- synthetic benign, to reproduce the baseline first
    python scripts/train_on_traces.py \
        --malicious dataset/combined/malicious.json \
        --benign    dataset/combined/benign.json
"""

from __future__ import annotations

import argparse
import json
import math
import os
import random
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parent.parent
TRAINING = REPO / "fragbench-structural-graph-main" / "training"
sys.path.insert(0, str(TRAINING))

from fragguard_gbt import FragmentFeatureEngine  # noqa: E402

# ── tool -> capability ─────────────────────────────────────────────────────
# Substring rules over MCP tool names, mapped onto the capability vocabulary
# the feature engine already knows. Deliberately coarse: these feed kill-chain
# completion features, and over-fitting the mapping to campaign names would be
# a way of smuggling the label in.
CAP_RULES = [
    (("read_file", "list_director", "glob", "file_info", "search_files",
      "read_"), "file_read"),
    (("write_file", "edit_file", "append", "create_director", "move_path",
      "copy_path", "create_archive"), "file_write"),
    (("run_command", "execute", "terminal", "shell", "spawn"), "process_exec"),
    (("encrypt", "decrypt", "hash", "encode", "crypto", "wallet"), "crypto"),
    (("credential", "password", "secret", "token", "keychain", "bruteforce",
      "ssh_"), "credential_access"),
    (("upload", "exfil", "send_", "post_", "http_request", "webhook",
      "compose_email", "smtp"), "network_outbound"),
    (("listen", "bind", "callback", "c2_", "beacon"), "network_listen"),
    (("scan", "recon", "osint", "subdomain", "whois", "dns", "enumerate",
      "discover", "probe"), "recon"),
    (("persist", "cron", "startup", "service_install", "registry"), "persistence"),
    (("obfuscate", "evasion", "pack", "polymorph"), "evasion"),
]

RESOURCE_RE = re.compile(
    r"(?:/[\w.\-]+){2,}"                       # posix-ish paths
    r"|[\w\-]+\.(?:csv|json|md|txt|log|db|sql|pem|key|zip|tar|gz|xlsx|ya?ml)"
    r"|https?://[\w.\-/]+"                     # urls
    r"|\b(?:\d{1,3}\.){3}\d{1,3}\b"            # ipv4
)

MAX_RESOURCE_FANOUT = 16   # README: cap fan-out per resource to avoid hub explosion


def capabilities_for(tool: str) -> set[str]:
    t = (tool or "").lower()
    return {cap for keys, cap in CAP_RULES if any(k in t for k in keys)}


def shannon(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def parse_ts(ts) -> float:
    if isinstance(ts, (int, float)):
        return float(ts)
    if isinstance(ts, str):
        try:
            from datetime import datetime
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
        except Exception:
            return 0.0
    return 0.0


def load(path: str, label: int, sample: int | None, seed: int):
    """Return list of samples; each sample is a flat list of its events."""
    with open(path) as f:
        d = json.load(f)
    samples = [[e for frag in var for e in frag] for var in d["sessions"]]
    samples = [s for s in samples if s]
    if sample and sample < len(samples):
        random.Random(seed).shuffle(samples)
        samples = samples[:sample]
    print(f"  {os.path.basename(path):<28} label={label}  "
          f"samples={len(samples):>5}  events={sum(len(s) for s in samples):>7}")
    return [(s, label) for s in samples]


def build_graph(corpus):
    """Return adj_list, node_metadata, edge_types_map, labels, sample_of_node."""
    adj = defaultdict(list)
    edge_types: dict[tuple[int, int], int] = {}
    meta: dict[int, dict] = {}
    labels: list[int] = []
    sample_of: list[int] = []

    nid = 0
    for s_idx, (events, label) in enumerate(corpus):
        by_session: dict[str, list[int]] = defaultdict(list)
        pending_call: dict[tuple[str, int], int] = {}
        resources: dict[str, list[int]] = defaultdict(list)

        for ev in events:
            args = ev.get("arguments")
            args_txt = args if isinstance(args, str) else json.dumps(args or "")
            sid = str(ev.get("session_id") or f"s{s_idx}")

            meta[nid] = {
                "session_id": hash(sid) & 0x7FFFFFFF,
                "user_id": s_idx,
                "timestamp": parse_ts(ev.get("ts")),
                "api_calls": {ev.get("tool") or "unknown"},
                "capabilities": capabilities_for(ev.get("tool")),
                "string_entropy": shannon(args_txt[:4000]),
                # arguments size as a complexity proxy, log-scaled like the
                # generator's own code_complexity range
                "code_complexity": math.log1p(ev.get("arguments_bytes")
                                              or ev.get("result_bytes") or 0),
                # No static analyser exists for MCP traces. Both of these are
                # label-correlated in the synthetic generator, so they are held
                # at zero rather than invented -- inventing them would leak.
                "obfuscation_score": 0.0,
                "static_risk_score": 0.0,
                "risk_score": 0.0,
            }
            labels.append(label)
            sample_of.append(s_idx)

            # 1 temporal: consecutive events within a session
            if by_session[sid]:
                prev = by_session[sid][-1]
                adj[prev].append(nid)
                adj[nid].append(prev)
                edge_types[(prev, nid)] = 1
            by_session[sid].append(nid)

            # 0 data_flow: tool_call_index <-> tool_result_index in a session
            if ev.get("event") == "tool_call" and ev.get("tool_call_index") is not None:
                pending_call[(sid, ev["tool_call_index"])] = nid
            elif ev.get("event") == "tool_result" and ev.get("tool_result_index") is not None:
                src = pending_call.pop((sid, ev["tool_result_index"]), None)
                if src is not None:
                    adj[src].append(nid)
                    adj[nid].append(src)
                    edge_types[(src, nid)] = 0

            # 2 shared_resource: same path / url / host in arguments
            for res in set(RESOURCE_RE.findall(args_txt[:2000])):
                bucket = resources[res]
                for other in bucket[-MAX_RESOURCE_FANOUT:]:
                    adj[other].append(nid)
                    adj[nid].append(other)
                    edge_types.setdefault((other, nid), 2)
                bucket.append(nid)

            nid += 1

    for n in range(nid):
        adj.setdefault(n, [])
    return dict(adj), meta, edge_types, np.array(labels), np.array(sample_of)


def sample_disjoint_split(sample_of, labels, test_size, seed):
    """Hold out whole samples, stratified by label, so no chain spans the split."""
    by_label = defaultdict(list)
    for s in sorted(set(sample_of.tolist())):
        by_label[labels[sample_of == s][0]].append(s)
    rng = random.Random(seed)
    test_samples: set[int] = set()
    for lab, ss in by_label.items():
        rng.shuffle(ss)
        test_samples.update(ss[:max(1, int(round(len(ss) * test_size)))])
    mask = np.array([s in test_samples for s in sample_of])
    return ~mask, mask


def evaluate(name, y, prob, sample_of, out):
    from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                                 f1_score, roc_auc_score, average_precision_score)
    pred = (prob >= 0.5).astype(int)
    row = dict(model=name,
               acc=accuracy_score(y, pred),
               prec=precision_score(y, pred, zero_division=0),
               rec=recall_score(y, pred, zero_division=0),
               f1=f1_score(y, pred, zero_division=0),
               auc=roc_auc_score(y, prob) if len(set(y)) > 1 else float("nan"),
               ap=average_precision_score(y, prob))

    # per-sample rollup: max event probability, threshold swept for best F1
    s_prob, s_true = {}, {}
    for s, p, t in zip(sample_of, prob, y):
        s_prob[s] = max(s_prob.get(s, 0.0), p)
        s_true[s] = t
    ss = sorted(s_prob)
    sp = np.array([s_prob[s] for s in ss])
    st = np.array([s_true[s] for s in ss])
    best_f1, best_th = 0.0, 0.5
    for th in np.unique(np.round(sp, 3)):
        f = f1_score(st, (sp >= th).astype(int), zero_division=0)
        if f > best_f1:
            best_f1, best_th = f, th
    row.update(chain_f1=best_f1, chain_th=best_th, n_chains=len(ss))
    out.append(row)
    return row


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--malicious", default="dataset/combined/malicious.json")
    ap.add_argument("--benign", default="dataset/combined/benign.json")
    ap.add_argument("--malicious-sample", type=int)
    ap.add_argument("--benign-sample", type=int,
                    help="match the benign sample count across arms")
    ap.add_argument("--test-size", type=float, default=0.3)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--quick", action="store_true", help="GBT + logistic only")
    ap.add_argument("--json-out", help="write the results table here")
    args = ap.parse_args()

    print("=" * 78)
    print("  FragBench detectors on real MCP traces")
    print("=" * 78)
    print("\n[1/5] Loading corpora")
    corpus = (load(args.malicious, 1, args.malicious_sample, args.seed)
              + load(args.benign, 0, args.benign_sample, args.seed))

    print("\n[2/5] Building the fragment graph")
    t0 = time.perf_counter()
    adj, meta, etypes, labels, sample_of = build_graph(corpus)
    et_counts = Counter(etypes.values())
    print(f"  nodes={len(labels):,}  edges={len(etypes):,}  "
          f"({time.perf_counter()-t0:.1f}s)")
    print(f"  edge types: data_flow={et_counts[0]:,}  temporal={et_counts[1]:,}  "
          f"shared_resource={et_counts[2]:,}")
    print(f"  malicious events: {labels.sum():,} / {len(labels):,} "
          f"({100*labels.mean():.1f}%)")

    print("\n[3/5] Computing the 36 graph-structural features")
    t0 = time.perf_counter()
    X, node_ids = FragmentFeatureEngine().compute_all_features(adj, meta, etypes)
    y = labels[np.array(node_ids)]
    s_of = sample_of[np.array(node_ids)]
    print(f"  X={X.shape}  ({time.perf_counter()-t0:.1f}s)")

    print("\n[4/5] Chain-disjoint split")
    tr, te = sample_disjoint_split(s_of, y, args.test_size, args.seed)
    print(f"  train events={tr.sum():,} ({y[tr].sum():,} malicious)")
    print(f"  test  events={te.sum():,} ({y[te].sum():,} malicious)")
    print(f"  train chains={len(set(s_of[tr]))}  test chains={len(set(s_of[te]))}")

    print("\n[5/5] Training")
    from sklearn.ensemble import (RandomForestClassifier, AdaBoostClassifier,
                                  HistGradientBoostingClassifier)
    from sklearn.linear_model import LogisticRegression
    from sklearn.neural_network import MLPClassifier
    from sklearn.neighbors import KNeighborsClassifier
    from sklearn.svm import SVC
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler

    models = {"GBT": HistGradientBoostingClassifier(max_iter=300, random_state=args.seed),
              "LogisticRegression": make_pipeline(StandardScaler(),
                                                  LogisticRegression(max_iter=2000))}
    if not args.quick:
        models.update({
            "RandomForest": RandomForestClassifier(n_estimators=300, n_jobs=-1,
                                                   random_state=args.seed),
            "AdaBoost": AdaBoostClassifier(random_state=args.seed),
            "MLP": make_pipeline(StandardScaler(),
                                 MLPClassifier(hidden_layer_sizes=(128, 64),
                                               max_iter=400, random_state=args.seed)),
            "KNN": make_pipeline(StandardScaler(), KNeighborsClassifier(n_neighbors=15)),
            "SVM_RBF": make_pipeline(StandardScaler(),
                                     SVC(probability=True, random_state=args.seed)),
        })

    rows: list[dict] = []
    for name, model in models.items():
        t0 = time.perf_counter()
        model.fit(X[tr], y[tr])
        prob = model.predict_proba(X[te])[:, 1]
        r = evaluate(name, y[te], prob, s_of[te], rows)
        print(f"  {name:<20} F1={r['f1']:.4f}  AUC={r['auc']:.4f}  "
              f"AP={r['ap']:.4f}  chainF1={r['chain_f1']:.4f}  "
              f"({time.perf_counter()-t0:.1f}s)")

    rows.sort(key=lambda r: -r["f1"])
    print("\n" + "=" * 78)
    print(f"  {'model':<20} {'acc':>7} {'prec':>7} {'rec':>7} {'F1':>7} "
          f"{'AUC':>7} {'AP':>7} {'chainF1':>8}")
    print("-" * 78)
    for r in rows:
        print(f"  {r['model']:<20} {r['acc']:>7.4f} {r['prec']:>7.4f} "
              f"{r['rec']:>7.4f} {r['f1']:>7.4f} {r['auc']:>7.4f} "
              f"{r['ap']:>7.4f} {r['chain_f1']:>8.4f}")

    if args.json_out:
        with open(args.json_out, "w") as f:
            json.dump({"malicious": args.malicious, "benign": args.benign,
                       "n_events": int(len(y)), "results": rows}, f, indent=2)
        print(f"\nwrote {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
