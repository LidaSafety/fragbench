"""Graph-free baselines: fragment-only, session-level, user-level aggregate.

The edge-type ablation answers "which edges carry the signal". It does not
answer the reviewers' actual challenge:

    "The claim that cross-session graph modeling is necessary would be credible
     only if the cross-session representation provides a clear benefit beyond
     simpler user-level aggregation and local structure."

That needs the cheap alternatives the graph has to beat:

    fragment   score each event from its own attributes, no neighbours at all
    session    pool a session's events, classify the pool, assign to its events
    user       pool an actor's whole trace, classify that, assign to its events

All three are reported at the EVENT level on the same held-out split as the
graph conditions, so the rows drop straight into the ablation table. Pooled arms
predict once per group and propagate that prediction to every event in the
group -- which is what "user-level aggregation" means operationally, and it is
also why a pooled arm can beat a per-event one: it cannot make inconsistent
calls inside a group.

Features are node-intrinsic only (capability, argument entropy, non-printable
ratio, length, tool identity). No neighbourhood term appears anywhere, so any
gap to the graph conditions is attributable to structure rather than to a richer
feature set.

Run:
    python ablations/aggregation_baselines.py \
        --malicious dataset/combined/malicious.json \
        --benign    benign_executed.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
for rel in ("..", "../training", "../dataset"):
    sys.path.insert(0, os.path.normpath(os.path.join(HERE, rel)))

from train_gnn import campaign_disjoint_split  # noqa: E402
from real_edge_ablation import TOOL_CAP, _entropy, _nonprintable_ratio  # noqa: E402

CAPS = ["network_outbound", "network_listen", "file_read", "file_write",
        "process_exec", "crypto", "credential_access", "persistence",
        "evasion", "recon"]


def event_features(tool: str, args: str) -> np.ndarray:
    v = np.zeros(24, dtype=np.float32)
    cap = TOOL_CAP.get(tool)
    if cap in CAPS:
        v[CAPS.index(cap)] = 1.0
    v[10] = _entropy(args) / 8.0
    v[11] = _nonprintable_ratio(args)
    v[12] = min(len(args) / 200.0, 30.0) / 30.0
    v[13] = min(len(args.split()) / 100.0, 1.0)
    if tool:
        v[14 + (hash(tool) % 10)] = 1.0
    return v


def load(mal_path: str, ben_path: str):
    """Return X, y, session_of, user_of, campaign_info (event level)."""
    X, y, sess, user, groups = [], [], [], [], defaultdict(list)
    uid = 0
    for path, is_mal in ((mal_path, 1), (ben_path, 0)):
        if not path or not os.path.exists(path):
            continue
        d = json.load(open(path))
        src = d.get("malicious_source") or d.get("benign_source") or []
        for vi, var in enumerate(d.get("sessions", [])):
            fam = None
            if is_mal and vi < len(src):
                fam = src[vi].get("campaign") or src[vi].get("campaign_id")
            for frag in var:
                for ev in frag:
                    if ev.get("event") != "tool_call":
                        continue
                    a = ev.get("arguments")
                    if not isinstance(a, str):
                        a = json.dumps(a, sort_keys=True) if a is not None else ""
                    X.append(event_features(ev.get("tool"), a))
                    y.append(is_mal)
                    sess.append(ev.get("session_id") or f"{is_mal}v{vi}")
                    user.append(uid)
                    if is_mal:
                        groups[fam or f"malvar_{vi}"].append(len(X) - 1)
            uid += 1
    return (np.array(X), np.array(y, dtype=np.int64), np.array(sess),
            np.array(user), [{"nodes": v} for v in groups.values()])


def pool(X, groups_of, idx):
    """Mean/max/count per group over the given event indices."""
    buckets = defaultdict(list)
    for i in idx:
        buckets[groups_of[i]].append(i)
    keys = sorted(buckets, key=lambda k: str(k))
    feats = np.zeros((len(keys), X.shape[1] * 2 + 1), dtype=np.float32)
    for r, k in enumerate(keys):
        rows = X[buckets[k]]
        feats[r, :X.shape[1]] = rows.mean(axis=0)
        feats[r, X.shape[1]:-1] = rows.max(axis=0)
        feats[r, -1] = min(len(rows) / 50.0, 1.0)
    return keys, feats, buckets


def panel(seed):
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.neural_network import MLPClassifier
    from sklearn.svm import SVC
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler
    return {
        "SVM": make_pipeline(StandardScaler(), SVC(probability=True, random_state=seed)),
        "MLP": make_pipeline(StandardScaler(),
                             MLPClassifier(hidden_layer_sizes=(128, 64),
                                           max_iter=400, random_state=seed)),
        "GBT": HistGradientBoostingClassifier(max_iter=300, random_state=seed),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--malicious", default="dataset/combined/malicious.json")
    ap.add_argument("--benign", default="dataset/combined/benign.json")
    ap.add_argument("--test-size", type=float, default=0.2)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--json-out", default="ablation_aggregation_baselines.json")
    args = ap.parse_args()

    from sklearn.metrics import f1_score, accuracy_score, roc_auc_score

    print("=" * 92)
    print("  GRAPH-FREE BASELINES — event-level F1 on the ablation's split")
    print("=" * 92)
    X, y, sess, user, campaign_info = load(args.malicious, args.benign)
    print(f"  events={len(y):,}  malicious={y.sum():,}  "
          f"sessions={len(set(sess)):,}  users={len(set(user)):,}  "
          f"instances={len(campaign_info)}")

    tr_ids, te_ids, _, _ = campaign_disjoint_split(
        list(range(len(y))), y, campaign_info,
        test_size=args.test_size, random_state=args.seed)
    print(f"  train={len(tr_ids):,}  test={len(te_ids):,}\n")

    arms = {"fragment": None, "session": sess, "user": user}
    rows = []
    for arm, groups_of in arms.items():
        for name, model in panel(args.seed).items():
            if groups_of is None:
                model.fit(X[tr_ids], y[tr_ids])
                pe = model.predict_proba(X[te_ids])[:, 1]
            else:
                # Pool per group, fit on groups, then hand each event its
                # group's probability so the metric stays event-level.
                ktr, Ftr, btr = pool(X, groups_of, tr_ids)
                ytr = np.array([y[btr[k][0]] for k in ktr])
                model.fit(Ftr, ytr)
                kte, Fte, bte = pool(X, groups_of, te_ids)
                pg = model.predict_proba(Fte)[:, 1]
                lookup = dict(zip(kte, pg))
                pe = np.array([lookup[groups_of[i]] for i in te_ids])

            pred = (pe >= 0.5).astype(int)
            r = {"arm": arm, "model": name,
                 "f1": f1_score(y[te_ids], pred, zero_division=0),
                 "acc": accuracy_score(y[te_ids], pred),
                 "auc": roc_auc_score(y[te_ids], pe) if len(set(y[te_ids])) > 1 else float("nan")}
            rows.append(r)
            print(f"  {arm:<10} {name:<6} F1={r['f1']:.4f}  Ac={r['acc']:.4f}  AUC={r['auc']:.4f}")

    print("\n" + "=" * 92)
    print(f"  {'arm':<12}{'SVM':>12}{'MLP':>12}{'GBT':>12}   (event-level F1)")
    print("  " + "-" * 88)
    for arm in arms:
        cells = {r["model"]: r["f1"] for r in rows if r["arm"] == arm}
        print(f"  {arm:<12}" + "".join(f"{cells.get(m, float('nan')):>12.4f}"
                                       for m in ("SVM", "MLP", "GBT")))
    print("\n  Compare against the graph conditions: cross-session structure is only")
    print("  load-bearing if 'full' clears the best row here by a clear margin.")

    with open(args.json_out, "w") as f:
        json.dump({"malicious": args.malicious, "benign": args.benign,
                   "n_events": int(len(y)), "results": rows}, f, indent=2)
    print(f"\n  wrote {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
