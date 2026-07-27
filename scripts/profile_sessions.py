#!/usr/bin/env python3
"""
Profile FragBench session traces into a distributional target spec.

Used to mine the released synthetic benign corpus so that the executed-benign
control set (generated via benign campaign seeds and run through the MCP
harness) can be matched against the same per-theme tool mixes, byte-size
distributions and chain shapes.

The same profiler is intentionally able to read all three corpora so their
profiles are directly comparable:

  * triple-nested combined JSON   {is_malicious, sessions: [[[event]]]}
  * a directory of session_chain_<chain>_s<step>.jsonl files
  * the malicious side: attack_graph_*.json runs joined to logs/*.jsonl

Examples
--------
    # released synthetic benign
    python scripts/profile_sessions.py --benign-json benign.json \
        --out docs/profiles/benign_synthetic.json

    # same corpus, from the per-session jsonl files
    python scripts/profile_sessions.py --session-dir dataset/benign \
        --out docs/profiles/benign_synthetic.json

    # executed malicious side, for parity comparison
    python scripts/profile_sessions.py --malicious-dir dataset/attacks \
        --logs-dir logs --out docs/profiles/malicious_executed.json

    # compare two profiles field by field
    python scripts/profile_sessions.py --compare \
        docs/profiles/benign_synthetic.json docs/profiles/malicious_executed.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

# ---------------------------------------------------------------------------
# Theme rulebook
#
# The eight themes are the ones named in the paper. The keyword sets below were
# derived empirically from the /workspace/<name> vocabulary of the released
# benign corpus rather than written from intuition, so that the executed-benign
# campaigns can be authored to hit the same mix.
# ---------------------------------------------------------------------------

THEME_KEYWORDS: dict[str, tuple[str, ...]] = {
    "system_administration": (
        "yaml", "ini", "toml", "alert_rules", "metrics_config", "dashboard_config",
        "server_list", "installed_packages", "capacity_report", "runbook",
        "rollback_plan", "ops_report", "iac_template", "terraform", "raw_logs",
        "syslog", "systemd", "cron", "nginx", "postgresql", "disk", "capacity",
        "provisioning", "deployment_runbook", "patch", "uptime", "logs",
        "installed", "packages", "server", "database", "hardware", "metrics",
        "incident", "performance", "backup", "restore", "monitoring",
    ),
    "documentation": (
        "readme", "api_docs", "docs", "docs_site", "company_wiki", "wiki",
        "procedure_drafts", "troubleshooting_steps", "process_flowchart",
        "handbook", "glossary", "onboarding_doc", "style_guide", "adr",
        "architecture", "guide", "docx",
    ),
    "data_wrangling": (
        "cleaned", "contacts_cleaned", "cleaned_contacts", "categorized",
        "normalized", "dedup", "transactions", "raw_scores", "data_inventory",
        "validation_script", "etl", "reconcile", "parsed", "matrix", "analysis",
        "responses", "dedupe", "normalise",
    ),
    "it_support": (
        "ticket", "tickets", "categorized_tickets", "welcome_emails", "new_hires",
        "provisioned_accounts", "account_details", "validated_users", "helpdesk",
        "feedback_reports", "onboarding", "offboarding", "password_reset",
        "escalation", "sla", "support_queue", "asset_tag", "requests", "welcome",
        "accounts", "reset", "hires", "emails", "notification", "provisioned",
        "asset", "feedback",
    ),
    "compliance_auditing": (
        "compliance_report", "audit_report", "audit_findings", "access_review",
        "access_audit", "risk_register", "updated_register", "license_inventory",
        "remediation_plan", "validation_report", "procurement", "vendor_list",
        "attestation", "gdpr", "soc2", "iso27001", "compliance", "inventory",
        "license", "audit", "remediation", "risk", "findings", "register",
        "vendor", "gaps", "contracts",
    ),
    "course_preparation": (
        "syllabus", "lecture_notes", "lectures", "study_guide", "grading_rubric",
        "assignments", "submissions", "graded_exams", "exam_submissions",
        "practice_problems", "course_materials", "course_outline", "courses",
        "gradebook", "quiz", "rubric", "curriculum", "homework", "lecture",
        "study", "practice", "problems", "student", "exam", "grading",
    ),
    "personal_organisation": (
        "photos", "photos_organized", "photos_unsorted", "albums", "itinerary",
        "recipe_index", "recipe_collection", "recipes_structured", "recipes_cleaned",
        "reading_list", "categorized_expenses", "expenses", "budget", "travel",
        "packing", "journal", "receipts", "wishlist", "recipes", "recipe", "photo",
    ),
    "project_lifecycle": (
        "repos", "projects", "build_artifacts", "sprint", "backlog", "milestone",
        "retro", "roadmap", "pull_request", "pipeline", "repo", "changelog",
        "release", "release_notes",
    ),
}

_PATH_RE = re.compile(r"/workspace/([A-Za-z0-9_.\-/]+)")

# Resource extraction for cross-fragment linkage measurement.
#
# The two corpora disagree on path style: the executed malicious traces use
# mostly relative paths ("prep_notes.md", "."), while the synthetic benign
# corpus uses absolute "/workspace/..." paths. Matching on the normalised
# basename keeps the linkage measurement comparable across both.
_PATH_ARG_RE = re.compile(
    r'"(?:path|file_path|filename|file|source|destination|target|dest|src|output|input|archive_path)"'
    r'\s*:\s*"([^"]+)"'
)
_ABS_PATH_RE = re.compile(r"(/(?:workspace|var|etc|opt|tmp|home|srv|usr)/[A-Za-z0-9_.\-/]+)")
_IGNORED_RESOURCES = {"", ".", "..", "./", "/"}


def extract_resources(arguments: Any) -> tuple[set[str], Counter]:
    """Return (normalised resource basenames, path-style counts) for one event."""
    text = _as_text(arguments)
    style: Counter[str] = Counter()
    resources: set[str] = set()

    for raw in _PATH_ARG_RE.findall(text) + _ABS_PATH_RE.findall(text):
        candidate = raw.strip()
        if candidate in _IGNORED_RESOURCES:
            continue
        style["absolute" if candidate.startswith("/") else "relative"] += 1
        basename = os.path.basename(candidate.rstrip("/"))
        if basename and basename not in _IGNORED_RESOURCES:
            resources.add(basename.lower())

    return resources, style

# Fields that identify a synthetic-generation tell rather than real execution.
_PLACEHOLDER_UUID_RE = re.compile(
    r"^(?:a1b2c3d4|b2c3d4e5|c3d4e5f6|d4e5f6a7|e5f6a7b8|f6a7b8c9|a7b8c9d0|b8c9d0e1)-",
    re.IGNORECASE,
)


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value)
    except (TypeError, ValueError):
        return str(value)


def _chain_path_text(chain: Sequence[Sequence[dict]]) -> str:
    """Concatenate every /workspace path referenced by a chain's arguments.

    Keywords are matched as substrings of the raw path text rather than against
    word-split tokens, so compound filenames like ``compliance_report.pdf`` match
    the ``compliance_report`` keyword.
    """
    paths: list[str] = []
    for fragment in chain:
        for event in fragment:
            text = _as_text(event.get("arguments")).lower()
            paths.extend(_PATH_RE.findall(text))
            # tool names carry theme signal too (compose_email -> it_support)
            paths.append(str(event.get("tool") or "").lower())
    return " ".join(paths)


def score_themes(chain: Sequence[Sequence[dict]]) -> dict[str, int]:
    """Number of distinct keywords per theme present in the chain's paths.

    Distinct-keyword counting is used rather than raw frequency so that one
    very common generic filename cannot dominate the assignment.
    """
    text = _chain_path_text(chain)
    return {
        theme: sum(1 for keyword in keywords if keyword in text)
        for theme, keywords in THEME_KEYWORDS.items()
    }


def classify_theme(chain: Sequence[Sequence[dict]]) -> str:
    """Assign the single best-scoring theme, breaking ties deterministically."""
    scores = score_themes(chain)
    best = max(scores.values())
    if best == 0:
        return "unclassified"
    # Themes overlap heavily; tie-break alphabetically so runs are reproducible.
    return sorted(theme for theme, score in scores.items() if score == best)[0]


# ---------------------------------------------------------------------------
# Loaders -- each yields chains as list[fragment], fragment = list[event dict]
# ---------------------------------------------------------------------------


def _read_jsonl(path: Path) -> list[dict]:
    events: list[dict] = []
    with path.open(errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def load_combined_json(path: Path) -> Iterator[list[list[dict]]]:
    data = json.loads(path.read_text())
    for chain in data.get("sessions", []):
        yield [list(fragment) for fragment in chain]


def load_session_dir(directory: Path) -> Iterator[list[list[dict]]]:
    pattern = re.compile(r"session_chain_(.+)_s(\d+)\.jsonl$")
    chains: dict[str, list[tuple[int, Path]]] = defaultdict(list)
    for path in sorted(directory.glob("session_chain_*.jsonl")):
        match = pattern.search(path.name)
        if match:
            chains[match.group(1)].append((int(match.group(2)), path))
    for chain_id in sorted(chains):
        steps = sorted(chains[chain_id])
        yield [_read_jsonl(path) for _, path in steps]


def load_executed_logs(logs_dir: Path) -> Iterator[list[list[dict]]]:
    """Group raw harness session logs into chains using their own metadata.

    Each fragment execution writes one session log carrying ``run_id``,
    ``campaign`` and ``variation_index`` (identifying the chain) plus
    ``stage_index`` (the fragment's position). Grouping on those avoids needing
    the ``attack_graph_*.json`` files, which the public dataset does not ship.
    """
    chains: dict[tuple, list[tuple[int, Path]]] = defaultdict(list)
    for path in sorted(logs_dir.rglob("session_*.jsonl")):
        header: dict | None = None
        with path.open(errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    header = json.loads(line)
                except json.JSONDecodeError:
                    continue
                break
        if not header:
            continue
        key = (
            header.get("run_id"),
            header.get("campaign"),
            header.get("variation_index"),
        )
        try:
            stage = int(header.get("stage_index") or 0)
        except (TypeError, ValueError):
            stage = 0
        chains[key].append((stage, path))

    for key in sorted(chains, key=lambda k: tuple(str(x) for x in k)):
        chain: list[list[dict]] = []
        for _, path in sorted(chains[key]):
            events = [
                e for e in _read_jsonl(path)
                if e.get("event") in ("tool_call", "tool_result")
            ]
            if events:
                chain.append(events)
        if chain:
            yield chain


def load_malicious_runs(attacks_dir: Path, logs_dir: Path) -> Iterator[list[list[dict]]]:
    """Join each attack_graph run to its per-fragment session logs.

    Falls back to scanning ``logs_dir`` by session id when the recorded
    ``session_path`` points at a container path that is not present locally.
    """
    log_index: dict[str, Path] = {}
    for path in logs_dir.rglob("session_*.jsonl"):
        log_index.setdefault(path.name, path)

    graphs = sorted(attacks_dir.glob("attack_graph_*.json"))
    if not graphs:
        # public dataset flattens graph detail into attack_*_seed_*.json
        graphs = [
            p for p in sorted(attacks_dir.glob("attack_*_seed_*.json"))
            if "_meta" not in p.name
        ]

    for path in graphs:
        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        variation = data.get("variation") or {}
        fragments = variation.get("fragments") or data.get("fragments") or []
        chain: list[list[dict]] = []
        for fragment in fragments:
            session_path = fragment.get("session_path")
            if not session_path:
                continue
            candidate = log_index.get(os.path.basename(session_path))
            if candidate is None:
                continue
            events = [
                e for e in _read_jsonl(candidate)
                if e.get("event") in ("tool_call", "tool_result")
            ]
            if events:
                chain.append(events)
        if chain:
            yield chain


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------


def _percentiles(values: Sequence[float]) -> dict[str, float]:
    if not values:
        return {}
    ordered = sorted(values)

    def pick(fraction: float) -> float:
        index = min(len(ordered) - 1, int(round(fraction * (len(ordered) - 1))))
        return float(ordered[index])

    return {
        "n": len(ordered),
        "min": float(ordered[0]),
        "p50": pick(0.50),
        "p90": pick(0.90),
        "p99": pick(0.99),
        "max": float(ordered[-1]),
        "mean": round(statistics.fmean(ordered), 2),
    }


def _share(counter: Counter, limit: int | None = None) -> dict[str, float]:
    total = sum(counter.values()) or 1
    items = counter.most_common(limit)
    return {str(k): round(v / total, 4) for k, v in items}


class Accumulator:
    """Collects the distributional axes we need to match."""

    def __init__(self) -> None:
        self.n_chains = 0
        self.chain_lengths: Counter[int] = Counter()
        self.events_per_fragment: list[int] = []
        self.tools: Counter[str] = Counter()
        self.tool_calls: Counter[str] = Counter()
        self.arg_bytes: list[int] = []
        self.result_bytes: list[int] = []
        self.success: Counter[bool] = Counter()
        self.tool_call_index: Counter[str] = Counter()
        self.session_ids_per_chain: list[int] = []
        self.placeholder_sids = 0
        self.total_sids = 0
        self.shared_resource_fragments: list[int] = []
        self.resources_per_chain: list[int] = []
        self.first_seq: Counter[int] = Counter()
        self.seq_strides: Counter[int] = Counter()
        self.path_style: Counter[str] = Counter()

    def add_chain(self, chain: Sequence[Sequence[dict]]) -> None:
        self.n_chains += 1
        self.chain_lengths[len(chain)] += 1

        session_ids: set[str] = set()
        resource_to_fragments: dict[str, set[int]] = defaultdict(set)

        for fragment_index, fragment in enumerate(chain):
            self.events_per_fragment.append(len(fragment))
            seqs: list[int] = []
            for event in fragment:
                kind = event.get("event")
                tool = str(event.get("tool") or "")
                self.tools[tool] += 1
                if kind == "tool_call":
                    self.tool_calls[tool] += 1
                    self.tool_call_index[str(event.get("tool_call_index"))] += 1
                    if event.get("arguments_bytes") is not None:
                        self.arg_bytes.append(int(event["arguments_bytes"]))
                elif kind == "tool_result":
                    if event.get("result_bytes") is not None:
                        self.result_bytes.append(int(event["result_bytes"]))
                    self.success[bool(event.get("success"))] += 1

                sid = event.get("session_id")
                if sid:
                    session_ids.add(str(sid))
                    self.total_sids += 1
                    if _PLACEHOLDER_UUID_RE.match(str(sid)):
                        self.placeholder_sids += 1

                if isinstance(event.get("seq"), int):
                    seqs.append(event["seq"])

                resources, style = extract_resources(event.get("arguments"))
                self.path_style.update(style)
                for resource in resources:
                    resource_to_fragments[resource].add(fragment_index)

            if seqs:
                self.first_seq[seqs[0]] += 1
                for a, b in zip(seqs, seqs[1:]):
                    self.seq_strides[b - a] += 1

        self.session_ids_per_chain.append(len(session_ids))
        self.resources_per_chain.append(len(resource_to_fragments))
        self.shared_resource_fragments.append(
            sum(1 for frags in resource_to_fragments.values() if len(frags) > 1)
        )

    def summary(self) -> dict[str, Any]:
        total_results = sum(self.success.values()) or 1
        return {
            "n_chains": self.n_chains,
            "chain_length_hist": dict(sorted(self.chain_lengths.items())),
            "events_per_fragment": _percentiles(self.events_per_fragment),
            "tool_share": _share(self.tools, 30),
            "tool_call_share": _share(self.tool_calls, 30),
            "arguments_bytes": _percentiles(self.arg_bytes),
            "arguments_bytes_over_3000_share": round(
                sum(1 for b in self.arg_bytes if b > 3000) / (len(self.arg_bytes) or 1), 4
            ),
            "result_bytes": _percentiles(self.result_bytes),
            "result_bytes_over_5000_share": round(
                sum(1 for b in self.result_bytes if b > 5000) / (len(self.result_bytes) or 1), 4
            ),
            "success_rate": round(self.success[True] / total_results, 4),
            "failure_rate": round(self.success[False] / total_results, 4),
            "tool_call_index_share": _share(self.tool_call_index, 10),
            "session_ids_per_chain": _percentiles(self.session_ids_per_chain),
            "placeholder_session_id_share": round(
                self.placeholder_sids / (self.total_sids or 1), 4
            ),
            "distinct_resources_per_chain": _percentiles(self.resources_per_chain),
            "cross_fragment_shared_resources_per_chain": _percentiles(
                self.shared_resource_fragments
            ),
            "first_seq_share": _share(self.first_seq, 8),
            "seq_stride_share": _share(self.seq_strides, 8),
            "path_style_share": _share(self.path_style),
        }


def build_profile(chains: Iterable[Sequence[Sequence[dict]]], label: str) -> dict[str, Any]:
    overall = Accumulator()
    per_theme: dict[str, Accumulator] = defaultdict(Accumulator)
    soft_mix: dict[str, float] = defaultdict(float)

    for chain in chains:
        chain = [list(fragment) for fragment in chain]
        if not chain:
            continue
        overall.add_chain(chain)
        per_theme[classify_theme(chain)].add_chain(chain)

        # Soft mix spreads each chain across every theme it touches. Themes
        # overlap in this corpus, so the soft mix is the better authoring target.
        scores = score_themes(chain)
        total_score = sum(scores.values())
        if total_score:
            for theme, score in scores.items():
                if score:
                    soft_mix[theme] += score / total_score
        else:
            soft_mix["unclassified"] += 1.0

    theme_counts = {t: acc.n_chains for t, acc in per_theme.items()}
    total = sum(theme_counts.values()) or 1
    soft_total = sum(soft_mix.values()) or 1
    return {
        "label": label,
        "overall": overall.summary(),
        "theme_mix": {
            t: round(n / total, 4)
            for t, n in sorted(theme_counts.items(), key=lambda kv: -kv[1])
        },
        "theme_mix_soft": {
            t: round(w / soft_total, 4)
            for t, w in sorted(soft_mix.items(), key=lambda kv: -kv[1])
        },
        "per_theme": {
            t: acc.summary()
            for t, acc in sorted(per_theme.items(), key=lambda kv: -kv[1].n_chains)
        },
    }


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def print_report(profile: dict[str, Any]) -> None:
    overall = profile["overall"]
    print(f"\n=== profile: {profile['label']} ===")
    print(f"chains: {overall['n_chains']}")
    print(f"chain length histogram: {overall['chain_length_hist']}")
    ev = overall["events_per_fragment"]
    if ev:
        print(
            f"events/fragment: p50={ev['p50']:.0f} p90={ev['p90']:.0f} "
            f"max={ev['max']:.0f} mean={ev['mean']}"
        )
    ab = overall["arguments_bytes"]
    if ab:
        print(
            f"arguments_bytes: p50={ab['p50']:.0f} p90={ab['p90']:.0f} "
            f"p99={ab['p99']:.0f} max={ab['max']:.0f} "
            f"(>3000: {overall['arguments_bytes_over_3000_share']:.1%})"
        )
    rb = overall["result_bytes"]
    if rb:
        print(
            f"result_bytes:    p50={rb['p50']:.0f} p90={rb['p90']:.0f} "
            f"p99={rb['p99']:.0f} max={rb['max']:.0f} "
            f"(>5000: {overall['result_bytes_over_5000_share']:.1%})"
        )
    print(
        f"success={overall['success_rate']:.1%} failure={overall['failure_rate']:.1%}  "
        f"placeholder_session_ids={overall['placeholder_session_id_share']:.1%}"
    )
    print(f"tool_call_index: {overall['tool_call_index_share']}")
    print(f"first_seq: {overall['first_seq_share']}")
    print(f"path_style: {overall.get('path_style_share', {})}")
    xres = overall["cross_fragment_shared_resources_per_chain"]
    if xres:
        print(
            f"cross-fragment shared resources/chain: p50={xres['p50']:.0f} "
            f"p90={xres['p90']:.0f} max={xres['max']:.0f}"
        )
    print("\ntop tools (share of all events):")
    for tool, share in list(overall["tool_share"].items())[:14]:
        print(f"  {tool:<24} {share:6.2%}")

    print("\ntheme mix (hard single-label):")
    for theme, share in profile["theme_mix"].items():
        acc = profile["per_theme"][theme]
        lengths = acc["chain_length_hist"]
        print(f"  {theme:<26} {share:6.2%}  ({acc['n_chains']:>4} chains) lengths={lengths}")

    print("\ntheme mix (soft, overlapping -- use this as the authoring target):")
    for theme, share in profile.get("theme_mix_soft", {}).items():
        print(f"  {theme:<26} {share:6.2%}")

    print("\nper-theme dominant tools:")
    for theme in profile["theme_mix"]:
        tools = list(profile["per_theme"][theme]["tool_call_share"].items())[:6]
        rendered = ", ".join(f"{t}={s:.0%}" for t, s in tools)
        print(f"  {theme:<26} {rendered}")


def compare(profile_a: dict[str, Any], profile_b: dict[str, Any]) -> None:
    a, b = profile_a["overall"], profile_b["overall"]
    print(f"\n=== compare: {profile_a['label']} vs {profile_b['label']} ===")
    rows = [
        ("chains", a["n_chains"], b["n_chains"]),
        ("success_rate", f"{a['success_rate']:.1%}", f"{b['success_rate']:.1%}"),
        ("failure_rate", f"{a['failure_rate']:.1%}", f"{b['failure_rate']:.1%}"),
        (
            "placeholder_sids",
            f"{a['placeholder_session_id_share']:.1%}",
            f"{b['placeholder_session_id_share']:.1%}",
        ),
        (
            "tool_call_index 1/1",
            f"{a['tool_call_index_share'].get('1/1', 0):.1%}",
            f"{b['tool_call_index_share'].get('1/1', 0):.1%}",
        ),
        (
            "arg_bytes p50/p99",
            f"{a['arguments_bytes'].get('p50', 0):.0f}/{a['arguments_bytes'].get('p99', 0):.0f}",
            f"{b['arguments_bytes'].get('p50', 0):.0f}/{b['arguments_bytes'].get('p99', 0):.0f}",
        ),
        (
            "result_bytes p50/p99",
            f"{a['result_bytes'].get('p50', 0):.0f}/{a['result_bytes'].get('p99', 0):.0f}",
            f"{b['result_bytes'].get('p50', 0):.0f}/{b['result_bytes'].get('p99', 0):.0f}",
        ),
        (
            "events/fragment p50",
            f"{a['events_per_fragment'].get('p50', 0):.0f}",
            f"{b['events_per_fragment'].get('p50', 0):.0f}",
        ),
        (
            "events/fragment mean",
            f"{a['events_per_fragment'].get('mean', 0)}",
            f"{b['events_per_fragment'].get('mean', 0)}",
        ),
        (
            "absolute path share",
            f"{a.get('path_style_share', {}).get('absolute', 0):.1%}",
            f"{b.get('path_style_share', {}).get('absolute', 0):.1%}",
        ),
        (
            "x-frag shared res p50",
            f"{a['cross_fragment_shared_resources_per_chain'].get('p50', 0):.0f}",
            f"{b['cross_fragment_shared_resources_per_chain'].get('p50', 0):.0f}",
        ),
    ]
    width = max(len(r[0]) for r in rows)
    for name, left, right in rows:
        print(f"  {name:<{width}}  {str(left):>16}  {str(right):>16}")

    print("\n  chain length histograms")
    print(f"    {profile_a['label']}: {a['chain_length_hist']}")
    print(f"    {profile_b['label']}: {b['chain_length_hist']}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--benign-json", type=Path, help="combined {is_malicious, sessions} JSON")
    source.add_argument("--session-dir", type=Path, help="dir of session_chain_<id>_s<n>.jsonl")
    source.add_argument("--malicious-dir", type=Path, help="dir of attack_graph_*.json runs")
    source.add_argument(
        "--executed-logs-dir",
        type=Path,
        help="dir of harness session_*.jsonl logs, grouped into chains by log metadata",
    )
    parser.add_argument("--logs-dir", type=Path, default=Path("logs"), help="session log dir for --malicious-dir")
    parser.add_argument("--label", help="label for the profile (defaults to the source name)")
    parser.add_argument("--out", type=Path, help="write the profile JSON here")
    parser.add_argument("--compare", nargs=2, type=Path, metavar=("A", "B"), help="compare two profile JSON files")
    args = parser.parse_args(argv)

    if args.compare:
        left = json.loads(args.compare[0].read_text())
        right = json.loads(args.compare[1].read_text())
        compare(left, right)
        return 0

    if args.benign_json:
        chains = load_combined_json(args.benign_json)
        label = args.label or args.benign_json.stem
    elif args.session_dir:
        chains = load_session_dir(args.session_dir)
        label = args.label or args.session_dir.name
    elif args.malicious_dir:
        chains = load_malicious_runs(args.malicious_dir, args.logs_dir)
        label = args.label or args.malicious_dir.name
    elif args.executed_logs_dir:
        chains = load_executed_logs(args.executed_logs_dir)
        label = args.label or args.executed_logs_dir.name
    else:
        parser.error(
            "one of --benign-json / --session-dir / --malicious-dir / "
            "--executed-logs-dir / --compare is required"
        )
        return 2

    profile = build_profile(chains, label)
    print_report(profile)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(profile, indent=2))
        print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
