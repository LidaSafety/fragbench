#!/usr/bin/env python3
"""Normalize the malicious1/ and benign1/ datasets to a shared list-of-lists format.

Outputs:
  dataset/malicious.json  -- {is_malicious: true,  malicious_source: [...], sessions: [[...], ...]}
  dataset/benign.json     -- {is_malicious: false,                          sessions: [[...], ...]}

Each leaf in `sessions` is a list of `tool_call`/`tool_result` events, projected to a common
field set so the per-leaf schema is identical across the two classes.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

TOOL_CALL_FIELDS = (
    "seq", "ts", "event", "iteration", "tool",
    "arguments", "arguments_bytes", "tool_call_index", "session_id",
)
TOOL_RESULT_FIELDS = (
    "seq", "ts", "event", "iteration", "tool",
    "success", "result_preview", "result_bytes", "tool_result_index", "session_id",
)


def warn(msg: str) -> None:
    print(f"warn: {msg}", file=sys.stderr)


def parse_records(path: Path) -> list[dict]:
    """Parse a file as a stream of JSON records.

    Handles both line-delimited JSONL (malicious sessions) and pretty-printed
    concatenated JSON (benign sessions per _format_spec.md).
    """
    text = path.read_text(encoding="utf-8")
    records: list[dict] = []
    decoder = json.JSONDecoder()
    i, n = 0, len(text)
    while i < n:
        while i < n and text[i].isspace():
            i += 1
        if i >= n:
            break
        try:
            obj, end = decoder.raw_decode(text, i)
        except json.JSONDecodeError as e:
            nl = text.find("\n", i)
            warn(f"{path.name}: malformed record at offset {i}: {e}; skipping to next line")
            if nl == -1:
                break
            i = nl + 1
            continue
        records.append(obj)
        i = end
    return records


def project_event(rec: dict) -> dict | None:
    ev = rec.get("event")
    if ev == "tool_call":
        return {k: rec[k] for k in TOOL_CALL_FIELDS if k in rec}
    if ev == "tool_result":
        return {k: rec[k] for k in TOOL_RESULT_FIELDS if k in rec}
    return None


def pick_session_id(
    records: list[dict],
    run_id: str,
    campaign_id: str,
    fragment_index: int,
    prompt: str,
) -> str | None:
    """Pick the session_id from a multi-session JSONL whose start matches the fragment."""
    starts = [r for r in records if r.get("event") == "session_start"]
    matches = [
        r for r in starts
        if r.get("run_id") == run_id
        and r.get("campaign") == campaign_id
        and r.get("stage_index") == fragment_index
    ]
    if len(matches) == 1:
        return matches[0].get("session_id")

    # Fallback: longest-common-prefix match on user_query against fragment prompt.
    # Prompts can be edited in the attack_graph after dispatch, so exact-match isn't safe.
    by_sid: dict[str, list[dict]] = {}
    for r in records:
        sid = r.get("session_id")
        if sid is None:
            continue
        by_sid.setdefault(sid, []).append(r)

    best_sid, best_overlap = None, 0
    for sid, recs in by_sid.items():
        for r in recs:
            if r.get("event") != "user_query":
                continue
            q = r.get("query") or ""
            overlap = 0
            for a, b in zip(prompt, q):
                if a != b:
                    break
                overlap += 1
            if overlap > best_overlap:
                best_overlap = overlap
                best_sid = sid
    if best_sid is not None and best_overlap >= 32:
        return best_sid

    if matches:
        return matches[0].get("session_id")
    return None


_FNAME_RE = re.compile(r"^attack_graph_(?P<run>[0-9a-z_]+)_seed_(?P<seed>\d+)_.*\.json$")


def sort_key_attack_graph(p: Path) -> tuple:
    m = _FNAME_RE.match(p.name)
    if not m:
        return (p.name,)
    return (m.group("run"), int(m.group("seed")), p.name)


def build_malicious(malicious_dir: Path) -> tuple[list[list[list[dict]]], list[dict]]:
    runs_dir = malicious_dir / "runs"
    logs_dir = malicious_dir / "logs"
    files = sorted(runs_dir.glob("attack_graph_*.json"), key=sort_key_attack_graph)

    sessions: list[list[list[dict]]] = []
    sources: list[dict] = []

    for ag_path in files:
        try:
            ag = json.loads(ag_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            warn(f"{ag_path.name}: failed to parse attack_graph: {e}; skipping")
            continue

        run_id = ag.get("run_id")
        variation = ag.get("variation") or {}
        campaign_id = variation.get("campaign_id")
        seed = variation.get("seed")
        campaign = variation.get("campaign") or ag.get("campaign")
        fragments = sorted(
            variation.get("fragments") or [],
            key=lambda f: f.get("fragment_index", 0),
        )

        sources.append({
            "run_id": run_id,
            "seed": seed,
            "campaign": campaign,
            "campaign_id": campaign_id,
            "attack_graph_file": ag_path.name,
        })

        variation_events: list[list[dict]] = []
        for frag in fragments:
            session_path = frag.get("session_path") or ""
            basename = Path(session_path).name
            if not basename:
                warn(f"{ag_path.name}: fragment {frag.get('fragment_id')} has no session_path (verdict={frag.get('verdict')})")
                variation_events.append([])
                continue
            local = logs_dir / basename
            if not local.exists():
                warn(f"{ag_path.name}: session file {basename} missing on disk (fragment {frag.get('fragment_id')})")
                variation_events.append([])
                continue

            records = parse_records(local)
            sid = pick_session_id(
                records,
                run_id=run_id,
                campaign_id=campaign_id,
                fragment_index=frag.get("fragment_index"),
                prompt=frag.get("prompt") or "",
            )
            if sid is None:
                warn(f"{ag_path.name}: no session_id match in {basename} for fragment {frag.get('fragment_id')}")
                variation_events.append([])
                continue

            leaf: list[dict] = []
            for r in records:
                if r.get("session_id") != sid:
                    continue
                proj = project_event(r)
                if proj is not None:
                    leaf.append(proj)
            variation_events.append(leaf)

        sessions.append(variation_events)

    return sessions, sources


def build_benign(benign_dir: Path) -> list[list[list[dict]]]:
    files = sorted(p for p in benign_dir.glob("session_benign_*.jsonl") if not p.name.startswith("_"))
    out: list[list[list[dict]]] = []
    for p in files:
        records = parse_records(p)
        leaf: list[dict] = []
        for r in records:
            proj = project_event(r)
            if proj is not None:
                leaf.append(proj)
        out.append([leaf])
    return out


def main() -> int:
    here = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--malicious-dir", type=Path, default=here / "malicious1")
    ap.add_argument("--benign-dir", type=Path, default=here / "benign1")
    ap.add_argument("--out-dir", type=Path, default=here)
    ap.add_argument("--pretty", action="store_true", help="indent JSON output")
    args = ap.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)

    print(f"building malicious from {args.malicious_dir} ...", file=sys.stderr)
    mal_sessions, mal_sources = build_malicious(args.malicious_dir)
    print(f"  variations: {len(mal_sessions)}, fragments: {sum(len(v) for v in mal_sessions)}", file=sys.stderr)

    print(f"building benign from {args.benign_dir} ...", file=sys.stderr)
    ben_sessions = build_benign(args.benign_dir)
    print(f"  sessions: {len(ben_sessions)}", file=sys.stderr)

    indent = 2 if args.pretty else None

    mal_out = args.out_dir / "malicious.json"
    with mal_out.open("w", encoding="utf-8") as f:
        json.dump(
            {"is_malicious": True, "malicious_source": mal_sources, "sessions": mal_sessions},
            f, indent=indent,
        )
    print(f"wrote {mal_out} ({mal_out.stat().st_size:,} bytes)", file=sys.stderr)

    ben_out = args.out_dir / "benign.json"
    with ben_out.open("w", encoding="utf-8") as f:
        json.dump({"is_malicious": False, "sessions": ben_sessions}, f, indent=indent)
    print(f"wrote {ben_out} ({ben_out.stat().st_size:,} bytes)", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
