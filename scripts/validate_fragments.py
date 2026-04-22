"""
Coherence validator for generated FragBench fragment JSON.

Runs three structural checks per variation and reports violations:

  1. chain_closure    — every fragment's ``consumes`` was ``produced`` by an
                        earlier fragment in the same variation (within the
                        same attack sub-chain).
  2. prompt_shape     — the direct-style prompt has length >= MIN_LEN and
                        ends in terminal punctuation (. ! ? or a quoted form).
  3. no_dangling_tail — the direct-style prompt does not end on a bare
                        preposition / conjunction (a regex split smell).

Usage:
    python scripts/validate_fragments.py results/promptsteal_fragments.json
    python scripts/validate_fragments.py results/promptsteal_fragments.json \\
        --log logs/coherence_promptsteal_42.json

Exit code:
    0 — all variations pass all hard checks
    1 — at least one variation has a hard violation (chain_closure fails, or
        a direct prompt fails prompt_shape)
    2 — script error (missing file, bad JSON, etc.)

no_dangling_tail emits warnings, not hard failures — prepositions at the tail
of a prompt are a strong signal but sometimes legitimate.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

MIN_LEN = 20

# Words that, if they end a prompt, usually mean a regex split cut the
# sentence in half. "To" and "from" are the worst offenders from the old
# `_template_fragment` splitter.
_DANGLING_TAIL = re.compile(
    r"\b(?:to|from|the|and|with|for|of|on|at|by|into|as)\s*[.!?]?\s*$",
    re.IGNORECASE,
)

# Prompts may legitimately end with a path, quoted filename, URL, or email —
# treat those as acceptable "terminal" forms alongside . ! ?
_TERMINAL = re.compile(r"""[.!?)"']\s*$""")


@dataclass
class Violation:
    variation_seed: int
    fragment_index: int
    check: str
    severity: str  # "error" or "warning"
    message: str


@dataclass
class Report:
    path: str
    total_variations: int = 0
    total_fragments: int = 0
    violations: list[Violation] = field(default_factory=list)

    @property
    def errors(self) -> list[Violation]:
        return [v for v in self.violations if v.severity == "error"]

    @property
    def warnings(self) -> list[Violation]:
        return [v for v in self.violations if v.severity == "warning"]

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "total_variations": self.total_variations,
            "total_fragments": self.total_fragments,
            "error_count": len(self.errors),
            "warning_count": len(self.warnings),
            "violations": [v.__dict__ for v in self.violations],
        }


def _direct_prompt(fragment: dict) -> str:
    for v in fragment.get("variations", []):
        if v.get("style") == "direct":
            return v.get("prompt", "")
    return ""


def check_chain_closure(seed: int, fragments: list[dict]) -> list[Violation]:
    """Every consumes must be produced by an earlier fragment."""
    out: list[Violation] = []
    produced_so_far: set[str] = set()
    for frag in fragments:
        idx = frag["fragment_index"]
        for artifact in frag.get("consumes", []):
            if artifact not in produced_so_far:
                out.append(Violation(
                    variation_seed=seed,
                    fragment_index=idx,
                    check="chain_closure",
                    severity="error",
                    message=f"consumes {artifact!r} but no earlier fragment produces it",
                ))
        for artifact in frag.get("produces", []):
            produced_so_far.add(artifact)
    return out


def check_prompt_shape(seed: int, fragments: list[dict]) -> list[Violation]:
    """Direct-style prompt must be long enough and terminally punctuated."""
    out: list[Violation] = []
    for frag in fragments:
        idx = frag["fragment_index"]
        p = _direct_prompt(frag).strip()
        if len(p) < MIN_LEN:
            out.append(Violation(
                variation_seed=seed,
                fragment_index=idx,
                check="prompt_shape",
                severity="error",
                message=f"direct prompt too short ({len(p)} chars < {MIN_LEN}): {p!r}",
            ))
        elif not _TERMINAL.search(p):
            out.append(Violation(
                variation_seed=seed,
                fragment_index=idx,
                check="prompt_shape",
                severity="error",
                message=f"direct prompt lacks terminal punctuation: ...{p[-40:]!r}",
            ))
    return out


def check_dangling_tail(seed: int, fragments: list[dict]) -> list[Violation]:
    """Prompt should not end on a bare preposition/conjunction."""
    out: list[Violation] = []
    for frag in fragments:
        idx = frag["fragment_index"]
        p = _direct_prompt(frag).strip()
        if _DANGLING_TAIL.search(p):
            out.append(Violation(
                variation_seed=seed,
                fragment_index=idx,
                check="no_dangling_tail",
                severity="warning",
                message=f"direct prompt ends on a preposition/conjunction: ...{p[-40:]!r}",
            ))
    return out


def validate_doc(doc: dict, path: str) -> Report:
    report = Report(path=path)
    for variation in doc.get("variations", []):
        seed = variation.get("seed", -1)
        fragments = variation.get("fragments", [])
        report.total_variations += 1
        report.total_fragments += len(fragments)
        report.violations.extend(check_chain_closure(seed, fragments))
        report.violations.extend(check_prompt_shape(seed, fragments))
        report.violations.extend(check_dangling_tail(seed, fragments))
    return report


def print_report(report: Report) -> None:
    print(f"Validating: {report.path}")
    print(f"  variations: {report.total_variations}   fragments: {report.total_fragments}")
    print(f"  errors:     {len(report.errors)}        warnings: {len(report.warnings)}")

    if not report.violations:
        print("  all checks passed.")
        return

    by_variation: dict[int, list[Violation]] = {}
    for v in report.violations:
        by_variation.setdefault(v.variation_seed, []).append(v)

    for seed in sorted(by_variation):
        print(f"\n  seed={seed}")
        for v in by_variation[seed]:
            tag = "ERR " if v.severity == "error" else "WARN"
            print(f"    [{tag}] frag={v.fragment_index} {v.check}: {v.message}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("json_path", help="Path to a fragments JSON file")
    parser.add_argument("--log", default=None, help="Optional JSON report output path")
    args = parser.parse_args()

    path = Path(args.json_path)
    if not path.exists():
        print(f"ERROR: file not found: {path}", file=sys.stderr)
        return 2
    try:
        doc = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        print(f"ERROR: invalid JSON in {path}: {e}", file=sys.stderr)
        return 2

    report = validate_doc(doc, str(path))
    print_report(report)

    if args.log:
        log_path = Path(args.log)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(json.dumps(report.to_dict(), indent=2))
        print(f"\nWrote report to {log_path}")

    return 1 if report.errors else 0


if __name__ == "__main__":
    sys.exit(main())
