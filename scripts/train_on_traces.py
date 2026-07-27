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
    """Return [(events, label, campaign)]; one entry per outer sample."""
    with open(path) as f:
        d = json.load(f)
    src = d.get("malicious_source") or d.get("benign_source") or []
    camps = [str((s or {}).get("campaign") or "UNKNOWN").lower() for s in src]
    rows = []
    for i, var in enumerate(d["sessions"]):
        events = [e for frag in var for e in frag]
        if events:
            rows.append((events, label,
                         camps[i] if i < len(camps) else ("benign" if not label else "unknown")))
    if sample and sample < len(rows):
        random.Random(seed).shuffle(rows)
        rows = rows[:sample]
    print(f"  {os.path.basename(path):<28} label={label}  "
          f"samples={len(rows):>5}  events={sum(len(r[0]) for r in rows):>7}  "
          f"campaigns={len({r[2] for r in rows})}")
    return rows


def build_graph(corpus):
    """Return adj_list, node_metadata, edge_types_map, labels, sample_of_node."""
    adj = defaultdict(list)
    edge_types: dict[tuple[int, int], int] = {}
    meta: dict[int, dict] = {}
    labels: list[int] = []
    sample_of: list[int] = []
    campaign_of: list[str] = []

    nid = 0
    for s_idx, (events, label, campaign) in enumerate(corpus):
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
            campaign_of.append(campaign)

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
    return (dict(adj), meta, edge_types, np.array(labels),
            np.array(sample_of), np.array(campaign_of))


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


def capture_probs(module):
    """Record the (y_true, y_prob) each training call scores.

    train_single_arch and train_ml_methods compute probabilities internally but
    return only metrics. Rather than fork them -- which would make the training
    loop ours and therefore a candidate artifact -- we shim the first metric
    function they call on the finished predictions and keep a copy.
    """
    captured: list[tuple] = []
    original = module.roc_auc_score

    def shim(y_true, y_score, *a, **kw):
        captured.append((np.asarray(y_true), np.asarray(y_score)))
        return original(y_true, y_score, *a, **kw)

    module.roc_auc_score = shim
    return captured, (lambda: setattr(module, "roc_auc_score", original))


def per_campaign_table(y, prob, campaign_of, models_probs):
    """Table 3 protocol: each campaign's positive events + ALL benign test events."""
    from sklearn.metrics import f1_score, accuracy_score
    benign = y == 0
    rows = []
    for camp in sorted({c for c, lab in zip(campaign_of, y) if lab == 1}):
        sel = benign | ((y == 1) & (campaign_of == camp))
        row = {"campaign": camp, "n_pos": int(((y == 1) & (campaign_of == camp)).sum())}
        for name, p in models_probs.items():
            pred = (p[sel] >= 0.5).astype(int)
            row[f"{name}_f1"] = f1_score(y[sel], pred, zero_division=0)
            row[f"{name}_ac"] = accuracy_score(y[sel], pred)
        rows.append(row)
    return rows


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
    ap.add_argument("--no-gnn", action="store_true",
                    help="classical baselines only (skips torch entirely)")
    ap.add_argument("--epochs", type=int, default=30, help="GNN epochs (compare_gnns uses 30)")
    ap.add_argument("--json-out", help="write the results table here")
    ap.add_argument("--csv-out", default="per_campaign_test.csv",
                    help="per-campaign table as CSV (Table 3 layout)")
    args = ap.parse_args()

    print("=" * 78)
    print("  FragBench detectors on real MCP traces")
    print("=" * 78)
    print("\n[1/5] Loading corpora")
    corpus = (load(args.malicious, 1, args.malicious_sample, args.seed)
              + load(args.benign, 0, args.benign_sample, args.seed))

    print("\n[2/5] Building the fragment graph")
    t0 = time.perf_counter()
    adj, meta, etypes, labels, sample_of, campaign_of = build_graph(corpus)
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
    camp_of = campaign_of[np.array(node_ids)]
    print(f"  X={X.shape}  ({time.perf_counter()-t0:.1f}s)")

    print("\n[4/5] Outer-sample split (reusing campaign_disjoint_split)")
    import compare_gnns as CG
    from train_gnn import NeighborSampler, build_node_features, campaign_disjoint_split

    # Their splitter holds out whole "campaign instances" and splits the benign
    # remainder independently -- exactly the 70/30 outer-sample stratified split
    # Table 3 describes. One malicious sample = one instance.
    nid_arr = np.array(node_ids)
    campaign_info = []
    for s_id in sorted(set(s_of[y == 1].tolist())):
        campaign_info.append({"nodes": nid_arr[(s_of == s_id) & (y == 1)].tolist()})

    train_ids, test_ids, y_train, y_test = campaign_disjoint_split(
        list(range(len(y))), y, campaign_info,
        test_size=args.test_size, random_state=args.seed)
    print(f"  train events={len(train_ids):,} ({y_train.sum():,} malicious)")
    print(f"  test  events={len(test_ids):,} ({y_test.sum():,} malicious)")
    print(f"  held-out instances={len(campaign_info)} total malicious samples")

    print("\n[5/5] Training the Table 3 panel (compare_gnns functions, unmodified)")
    rows: list[dict] = []
    probs: dict[str, np.ndarray] = {}
    captured, restore = capture_probs(CG)

    try:
        if not args.no_gnn:
            import torch
            device = "cuda" if torch.cuda.is_available() else "cpu"
            feats = build_node_features(meta, list(range(len(y))),
                                        np.random.default_rng(args.seed))
            sampler = NeighborSampler(adj, etypes, feats, K1=10, K2=5, seed=args.seed)
            for arch in ("gcn", "sage", "gat", "gin"):
                name = CG.ARCH_DISPLAY[arch]
                mark = len(captured)
                m = CG.train_single_arch(
                    arch=arch, sampler=sampler,
                    train_ids=train_ids, y_train=y_train,
                    test_ids=test_ids, y_test=y_test,
                    epochs=args.epochs, batch_size=256, lr=1e-3, device=device)
                # the final capture of this call is the held-out scoring
                probs[name] = captured[-1][1] if len(captured) > mark else None
                rows.append({"model": name, "f1": m["f1"], "acc": m["accuracy"],
                             "prec": m["precision"], "rec": m["recall"],
                             "auc": m["roc_auc"], "ap": m["avg_precision"]})
                print(f"  {name:<12} F1={m['f1']:.4f}  Ac={m['accuracy']:.4f}  "
                      f"AUC={m['roc_auc']:.4f}  ({m['train_time_s']:.0f}s)")

        # train_single_arch also scores mid-training for checkpoint selection, so
        # `captured` holds several entries per GNN. Mark the position before the
        # classical panel and take only what that call appends -- one per model,
        # in the order train_ml_methods trains them.
        mark = len(captured)
        ml = CG.train_ml_methods(adj, meta, etypes,
                                 train_ids, y_train, test_ids, y_test)
        ml_probs = [c[1] for c in captured[mark:]]
        if len(ml_probs) != len(ml):
            print(f"  WARNING: captured {len(ml_probs)} probability vectors for "
                  f"{len(ml)} classical models; per-campaign columns would be "
                  f"misaligned, so they are omitted.")
            ml_probs = []
        for i, m in enumerate(ml):
            name = m.get("display_name") or m.get("arch")
            if i < len(ml_probs):
                probs[name] = ml_probs[i]
            rows.append({"model": name, "f1": m["f1"], "acc": m["accuracy"],
                         "prec": m["precision"], "rec": m["recall"],
                         "auc": m["roc_auc"], "ap": m["avg_precision"]})
    finally:
        restore()

    for r in rows:
        r.setdefault("chain_f1", float("nan"))

    # Table 3 reports exactly seven detectors; train_ml_methods returns eleven.
    TABLE3 = ["GCN", "GraphSAGE", "GAT", "GIN", "svm", "mlp_sk", "gbt"]
    LABEL = {"svm": "SVM", "mlp_sk": "MLP", "gbt": "GBT"}
    cols = [m for m in TABLE3 if m in probs]

    camp_rows = per_campaign_table(y_test, None, camp_of[test_ids], probs)
    print("\n" + "=" * 78)
    print("  PER-CAMPAIGN, HELD-OUT TEST EVENTS")
    print("  (each campaign's positive test events + all benign test events)")
    print("=" * 78)
    hdr = f"  {'campaign':<30}" + "".join(f"{LABEL.get(m, m):>16}" for m in cols)
    sub = f"  {'':<30}" + "".join(f"{'F1':>8}{'Ac':>8}" for _ in cols)
    print(hdr + "\n" + sub + "\n  " + "-" * (len(hdr) - 2))
    for cr in camp_rows:
        print(f"  {cr['campaign']:<30}" +
              "".join(f"{cr[f'{m}_f1']:>8.3f}{cr[f'{m}_ac']:>8.3f}" for m in cols))

    agg = {r["model"]: r for r in rows}
    print("  " + "-" * (len(hdr) - 2))
    print(f"  {'AGGREGATE':<30}" +
          "".join(f"{agg[m]['f1']:>8.3f}{agg[m]['acc']:>8.3f}"
                  if m in agg else f"{'':>16}" for m in cols))

    if args.csv_out:
        import csv
        with open(args.csv_out, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["campaign", "n_pos"] +
                       [f"{LABEL.get(m, m)}_{k}" for m in cols for k in ("F1", "Ac")])
            for cr in camp_rows:
                w.writerow([cr["campaign"], cr["n_pos"]] +
                           [round(cr[f"{m}_{k}"], 4) for m in cols for k in ("f1", "ac")])
            w.writerow(["AGGREGATE", int(y_test.sum())] +
                       [round(agg[m][k], 4) if m in agg else ""
                        for m in cols for k in ("f1", "acc")])
        print(f"\n  wrote {args.csv_out}")

    rows.sort(key=lambda r: -r["f1"])
    print("\n" + "=" * 78)
    print(f"  {'model':<20} {'acc':>7} {'prec':>7} {'rec':>7} {'F1':>7} "
          f"{'AUC':>7} {'AP':>7}")
    print("-" * 78)
    for r in rows:
        print(f"  {r['model']:<20} {r['acc']:>7.4f} {r['prec']:>7.4f} "
              f"{r['rec']:>7.4f} {r['f1']:>7.4f} {r['auc']:>7.4f} "
              f"{r['ap']:>7.4f}")

    if args.json_out:
        with open(args.json_out, "w") as f:
            json.dump({"malicious": args.malicious, "benign": args.benign,
                       "n_events": int(len(y)), "results": rows,
                       "per_campaign": camp_rows}, f, indent=2)
        print(f"\nwrote {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
