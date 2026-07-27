"""Typed interaction edges over real MCP traces (paper Step 2 + SimHash).

Consumed by ablations/real_edge_ablation.py:

    edges = build_edges(nodes, sessions)     # edges[t] -> [(i, j), ...]

    nodes    [{"id", "session_id", "arguments", "tool", "label"}, ...]
    sessions {session_id: [node_id, ...]}    in arrival order

Edge type ids follow models.EDGE_TYPES plus the SimHash edge the released
generator never built:

    0 data_flow           a write's resource is later read, same session
    1 temporal            consecutive events in a session
    2 shared_resource     same resource, DIFFERENT sessions
    3 shared_session      same session, non-consecutive
    4 argument_similarity 64-bit SimHash within Hamming 8, DIFFERENT sessions

The within/cross split the ablation relies on (WITHIN={0,1,3}, CROSS={2,4}) is
enforced here rather than assumed: 0/1/3 never leave a session and 2/4 never
stay inside one. If that were not true, "cross_session_only" would silently
retain within-session signal and the ablation would understate the graph's
dependence on cross-session structure -- the exact question being asked.

Nodes are tool_call events only, so data_flow cannot be the call/result pairing
used elsewhere; it is the producer->consumer relation instead, which is what
"output of A feeds into B" means when results are not themselves nodes.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict

# Fan-out caps. Without them a single common path (/workspace/report.md, seen by
# hundreds of chains) becomes a hub joining unrelated components, which inflates
# every neighbourhood feature and destroys the ablation's contrast.
MAX_RESOURCE_FANOUT = 16
MAX_SESSION_FANOUT = 16
MAX_SIMHASH_FANOUT = 8

SIMHASH_BITS = 64
SIMHASH_BANDS = 8               # 8 bands x 8 bits; candidates share a band
SIMHASH_MAX_HAMMING = 8         # README Layer 3, item 8

RESOURCE_RE = re.compile(
    r"(?:/[\w.\-]+){2,}"
    r"|[\w\-]+\.(?:csv|json|md|txt|log|db|sql|pem|key|zip|tar|gz|xlsx|ya?ml|php|sh|py)"
    r"|https?://[\w.\-/]+"
    r"|\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

WRITE_HINTS = ("write", "append", "edit", "create", "move", "copy", "stage",
               "archive", "delete", "permission")
READ_HINTS = ("read", "list", "glob", "search", "info", "cat", "load")


def _resources(text: str) -> set[str]:
    return set(RESOURCE_RE.findall(text[:2000]))


def _is_write(tool: str) -> bool:
    t = (tool or "").lower()
    return any(h in t for h in WRITE_HINTS)


def _is_read(tool: str) -> bool:
    t = (tool or "").lower()
    return any(h in t for h in READ_HINTS)


def _tokens(text: str) -> list[str]:
    return re.findall(r"[A-Za-z0-9_./\-]{3,}", text[:2000].lower())


def simhash(text: str) -> int:
    """64-bit SimHash over argument tokens."""
    toks = _tokens(text)
    if not toks:
        return 0
    v = [0] * SIMHASH_BITS
    for tok in toks:
        h = int.from_bytes(hashlib.blake2b(tok.encode(), digest_size=8).digest(), "big")
        for b in range(SIMHASH_BITS):
            v[b] += 1 if (h >> b) & 1 else -1
    out = 0
    for b in range(SIMHASH_BITS):
        if v[b] > 0:
            out |= 1 << b
    return out


def _hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


def build_edges(nodes, sessions) -> dict[int, list[tuple[int, int]]]:
    edges: dict[int, list[tuple[int, int]]] = {t: [] for t in range(5)}
    by_id = {n["id"]: n for n in nodes}
    session_of = {n["id"]: n["session_id"] for n in nodes}

    # ── 1 temporal, 3 shared_session ─────────────────────────────────────
    for sid, members in sessions.items():
        ordered = sorted(members)
        for a, b in zip(ordered, ordered[1:]):
            edges[1].append((a, b))
        for pos, nid in enumerate(ordered):
            # non-consecutive pairs only; the consecutive one is temporal
            for other in ordered[max(0, pos - MAX_SESSION_FANOUT):max(0, pos - 1)]:
                edges[3].append((other, nid))

    # ── 0 data_flow: write of a resource -> later read of it, same session
    for sid, members in sessions.items():
        written: dict[str, int] = {}
        for nid in sorted(members):
            n = by_id[nid]
            res = _resources(n["arguments"])
            if _is_read(n["tool"]):
                for r in res:
                    src = written.get(r)
                    if src is not None and src != nid:
                        edges[0].append((src, nid))
            if _is_write(n["tool"]):
                for r in res:
                    written[r] = nid

    # ── 2 shared_resource: same resource, different sessions ─────────────
    holders: dict[str, list[int]] = defaultdict(list)
    for n in nodes:
        for r in _resources(n["arguments"]):
            holders[r].append(n["id"])
    for r, ids in holders.items():
        ids.sort()
        for pos, nid in enumerate(ids):
            linked = 0
            for other in reversed(ids[:pos]):
                if session_of[other] == session_of[nid]:
                    continue          # within-session belongs to 1/3, not here
                edges[2].append((other, nid))
                linked += 1
                if linked >= MAX_RESOURCE_FANOUT:
                    break

    # ── 4 argument_similarity: SimHash, banded LSH, different sessions ───
    band_bits = SIMHASH_BITS // SIMHASH_BANDS
    buckets: dict[tuple[int, int], list[int]] = defaultdict(list)
    sig: dict[int, int] = {}
    for n in nodes:
        h = simhash(n["arguments"])
        if h == 0:
            continue
        sig[n["id"]] = h
        for band in range(SIMHASH_BANDS):
            key = (band, (h >> (band * band_bits)) & ((1 << band_bits) - 1))
            buckets[key].append(n["id"])

    seen: set[tuple[int, int]] = set()
    for key, ids in buckets.items():
        if len(ids) < 2 or len(ids) > 512:      # runaway bucket: uninformative
            continue
        ids.sort()
        for pos, nid in enumerate(ids):
            linked = 0
            for other in reversed(ids[:pos]):
                if session_of[other] == session_of[nid]:
                    continue
                pair = (other, nid)
                if pair in seen:
                    continue
                if _hamming(sig[other], sig[nid]) <= SIMHASH_MAX_HAMMING:
                    seen.add(pair)
                    edges[4].append(pair)
                    linked += 1
                    if linked >= MAX_SIMHASH_FANOUT:
                        break
    return edges


if __name__ == "__main__":
    import sys
    payloads = sys.argv[1:] or ["dataset/combined/malicious.json"]
    nodes, sessions = [], defaultdict(list)
    for p in payloads:
        d = json.load(open(p))
        mal = bool(d.get("is_malicious"))
        for vi, var in enumerate(d.get("sessions", [])):
            for frag in var:
                for ev in frag:
                    if ev.get("event") != "tool_call":
                        continue
                    args = ev.get("arguments")
                    if not isinstance(args, str):
                        args = json.dumps(args, sort_keys=True) if args is not None else ""
                    sid = ev.get("session_id") or f"v{vi}"
                    nid = len(nodes)
                    nodes.append({"id": nid, "session_id": sid, "arguments": args,
                                  "tool": ev.get("tool"), "label": int(mal)})
                    sessions[sid].append(nid)
    e = build_edges(nodes, sessions)
    names = ["data_flow", "temporal", "shared_resource", "shared_session",
             "argument_similarity"]
    print(f"nodes={len(nodes):,}  sessions={len(sessions):,}")
    for t in range(5):
        print(f"  {names[t]:<20} {len(e[t]):>10,}")
