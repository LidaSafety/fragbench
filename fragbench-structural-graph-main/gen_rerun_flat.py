#!/usr/bin/env python3
"""Generate a flat rerun shell script from rl_tables_base.tex.

Emits one `bash ./run_grid.sh ...` invocation per (dataset, style, judge,
rewriter) cell that is either:
  - missing (`---` in the table), or
  - reported with a `(0.0)` / `(+0.0)` / `(-0.0)` delta (rewriter didn't move
    pass rate vs round-0 baseline — usually a failed run worth retrying).
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

# Display-name → canonical-model mappings. The judge form of GPT-5.4-mini
# omits the date suffix that the rewriter form carries (matches usage in
# rerun_local.sh / run_grid.sh).
JUDGES = [
    ("Llama-4",       "meta-llama/llama-guard-4-12b"),
    ("Sonnet~4.6",    "anthropic/claude-sonnet-4-6"),
    ("Opus~4.7",      "anthropic/claude-opus-4-6"),
    ("GPT-5.4-mini",  "openai/gpt-5.4-mini"),
]
REWRITERS_BY_COL = [
    "anthropic/claude-sonnet-4-6",
    "anthropic/claude-opus-4-6",
    "openai/gpt-5.4-mini-2026-03-17",
    "azure/gpt-5.4",
    "deepseek/deepseek-v4-flash",
]
JUDGE_TO_MODEL = dict(JUDGES)

TABLE_RE = re.compile(
    r"%\s*table-key:\s*stem=([^;]+);\s*style=(\S+).*?"
    r"\\midrule(.*?)\\bottomrule",
    re.DOTALL,
)
ZERO_DELTA_RE = re.compile(r"\(\s*[+-]?0\.0+\s*\)$")


def parse_tables(tex: str):
    """Yield (stem, style, judge_model, rewriter_model) for every cell needing rerun."""
    for m in TABLE_RE.finditer(tex):
        stem, style, body = m.group(1).strip(), m.group(2).strip(), m.group(3)
        for raw_line in body.splitlines():
            line = raw_line.strip().rstrip("\\").strip()
            if not line:
                continue
            cells = [c.strip() for c in line.split("&")]
            if len(cells) != 6:
                continue
            judge_model = JUDGE_TO_MODEL.get(cells[0])
            if judge_model is None:
                continue
            for col, cell in enumerate(cells[1:]):
                if cell == "---" or ZERO_DELTA_RE.search(cell):
                    yield stem, style, judge_model, REWRITERS_BY_COL[col]


def emit(rows, out_path: Path):
    lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "set -a; source .env; set +a",
        "",
        "# Auto-generated from rl_tables_base.tex by gen_rerun_flat.py.",
        "# Includes cells that are --- (never run) AND cells with (0.0) / (+0.0) delta.",
        f"# Total cases: {len(rows)}",
        "",
    ]
    for stem, style, judge, rewriter in rows:
        lines.append(
            f"bash ./run_grid.sh --datasets=dataset/{stem}.json "
            f"--judges={judge} --styles={style} --rewriters={rewriter}"
        )
    out_path.write_text("\n".join(lines) + "\n")
    out_path.chmod(0o755)


def main():
    here = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tex", type=Path, default=here / "rl_tables_base.tex")
    ap.add_argument("--out", type=Path, default=here / "rerun_flat.sh")
    args = ap.parse_args()

    tex = args.tex.read_text(encoding="utf-8")
    rows = list(parse_tables(tex))

    emit(rows, args.out)
    print(f"wrote {args.out} ({len(rows)} cases)")
    by_stem: dict[str, int] = {}
    for stem, *_ in rows:
        by_stem[stem] = by_stem.get(stem, 0) + 1
    for stem, n in sorted(by_stem.items()):
        print(f"  {stem}: {n}")


if __name__ == "__main__":
    main()
