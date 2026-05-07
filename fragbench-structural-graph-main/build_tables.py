#!/usr/bin/env python3
"""build_tables.py — pivot judge × rewriter pass rates per (campaign, style).

Reads runs/ produced by fragbench_generated_rl.py and emits a table for
every (campaign_stem, variation_style) pair.

Run dir naming (from default_output_path):
  <stem>__<mode>__vs-<style>__judge-<judge_slug>__rewriter-<rewriter_slug>
   __max-<N>__<ts>
where _slugify replaces '/'/':'/' ' with '_'.

LaTeX output (`--format tex`, default layout):
  wrapped in `table`/`\\caption`/`\\label`, two-row rewriter header using
  `\\multicolumn` + `\\cmidrule`, short row/column titles (Llama-4, Sonnet~4.6,
  Opus~4.7, …). Use `--tex-tabular-only` for a bare tabular fragment.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

SLUG = lambda s: s.replace("/", "_").replace(":", "_").replace(" ", "_")


def parse_run_dir(name: str):
    """Return dict with stem/mode/style/judge_slug/rewriter_slug/max/ts or None."""
    parts = name.split("__")
    if len(parts) < 6:
        return None
    out = {"stem": parts[0], "mode": parts[1]}
    rest = parts[2:]
    for p in rest:
        if p.startswith("vs-"):
            out["style"] = p[3:]
        elif p.startswith("judge-"):
            out["judge_slug"] = p[6:]
        elif p.startswith("rewriter-"):
            out["rewriter_slug"] = p[9:]
        elif p.startswith("max-"):
            out["max"] = p[4:]
    out["ts"] = parts[-1]
    return out if {"style", "judge_slug"}.issubset(out) else None


def trajectory_rates(traj_path: Path) -> List[float]:
    """Load pass_rate series from run_trajectory.json."""
    try:
        traj = json.loads(traj_path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return []
    rates = []
    for t in traj:
        if isinstance(t, dict):
            r = t.get("pass_rate")
            if isinstance(r, (int, float)):
                rates.append(float(r))
    return rates


def metric_from_trajectory(traj_path: Path, agg: str) -> Optional[float]:
    rates = trajectory_rates(traj_path)
    if not rates:
        return None
    if agg == "final":
        return rates[-1]
    if agg == "first":
        return rates[0]
    return max(rates)


def baseline_final_delta(traj_path: Path) -> Tuple[Optional[float], Optional[float], Optional[float]]:
    """(pass_rate at index 0, at index -1, final - baseline)."""
    rates = trajectory_rates(traj_path)
    if not rates:
        return None, None, None
    b, f = rates[0], rates[-1]
    return b, f, f - b


def fmt_cell(v: Optional[float], missing: str = "—", pct: bool = True, places: int = 1) -> str:
    if v is None:
        return missing
    return f"{v * 100:.{places}f}" if pct else f"{v:.{places + 2}f}"


def fmt_cell_with_delta(
    baseline: Optional[float],
    final: Optional[float],
    delta: Optional[float],
    *,
    pct: bool = True,
    places: int = 1,
    show_baseline: bool = False,
    missing: str = "—",
    space_before_delta: bool = False,
) -> str:
    if final is None or delta is None:
        return missing
    f_str = fmt_cell(final, missing=missing, pct=pct, places=places)
    d_raw = delta * (100.0 if pct else 1.0)
    if d_raw > 0:
        d_str = f"+{abs(d_raw):.{places}f}"
    elif d_raw < 0:
        d_str = f"-{abs(d_raw):.{places}f}"
    else:
        d_str = f"{0:.{places}f}"
    core = (f"{f_str} ({d_str})") if space_before_delta else (f"{f_str}({d_str})")
    if show_baseline and baseline is not None:
        b_str = fmt_cell(baseline, pct=pct, places=places)
        return f"{core} [base {b_str}]"
    return core


def tex_escape(s: str) -> str:
    return (
        s.replace("\\", r"\textbackslash{}")
        .replace("&", r"\&")
        .replace("%", r"\%")
        .replace("#", r"\#")
        .replace("_", r"\_")
    )


CAMPAIGN_DISPLAY_TITLE = {
    "dprk_fraud_llm": "DPRK FRAUD",
    "promptsteal_llm": "PROMPTSTEAL",
    "quietvault_llm": "QUIETVAULT",
}


def campaign_title(stem: str) -> str:
    return CAMPAIGN_DISPLAY_TITLE.get(stem, stem.replace("_", " ").upper())


JUDGE_COL_SHORT = {
    "meta-llama/llama-guard-4-12b": r"Llama-4",
    "anthropic/claude-sonnet-4-6": r"Sonnet~4.6",
    "anthropic/claude-opus-4-6": r"Opus~4.7",
    "openai/gpt-5.4-mini": r"GPT-5.4-mini",
    "openai/gpt-5.4-mini-2026-03-17": r"GPT-5.4-mini",
}

REWRITER_COL_SHORT = {
    "anthropic/claude-sonnet-4-6": r"Sonnet~4.6",
    "anthropic/claude-opus-4-6": r"Opus~4.7",
    "openai/gpt-5.4-mini-2026-03-17": r"GPT-5.4-mini",
    "openai/gpt-5.4-mini": r"GPT-5.4-mini",
    "azure/gpt-5.4": r"GPT-5.4",
    "deepseek/deepseek-v4-flash": r"DeepSeek~V4~Flash",
}


def tex_short_judge(judge_id: str) -> str:
    if judge_id in JUDGE_COL_SHORT:
        return JUDGE_COL_SHORT[judge_id]
    return tex_escape(judge_id)


def tex_short_rewriter(rw_id: str) -> str:
    if rw_id in REWRITER_COL_SHORT:
        return REWRITER_COL_SHORT[rw_id]
    return tex_escape(rw_id)


def render_md(judges, rewriters, matrix, title):
    head = "| Judge \\ Rewriter | " + " | ".join(rewriters) + " |"
    sep = "|" + "---|" * (len(rewriters) + 1)
    rows = [
        f"| {j} | " + " | ".join(matrix.get((j, r), "—") for r in rewriters) + " |"
        for j in judges
    ]
    return f"### {title}\n\n{head}\n{sep}\n" + "\n".join(rows) + "\n"


def render_csv(judges, rewriters, matrix, title):
    out = [f"# {title}", "judge," + ",".join(rewriters)]
    for j in judges:
        out.append(f"{j}," + ",".join(matrix.get((j, r), "") for r in rewriters))
    return "\n".join(out) + "\n"


def round_word(n: int) -> str:
    words = {
        1: "one",
        2: "two",
        3: "three",
        4: "four",
        5: "five",
        6: "six",
        7: "seven",
        8: "eight",
        9: "nine",
        10: "ten",
    }
    return words.get(n, str(n))


def build_tex_table_caption(stem: str, style: str, *, rounds: int, pct: bool, show_delta: bool) -> str:
    ct = tex_escape(campaign_title(stem))
    st_esc = tex_escape(style)
    if show_delta:
        pct_bit = (
            r"Cells show final pass rate (\%); parentheses give $\Delta$ "
            r"from the round~0 baseline, in percentage points."
            if pct
            else (
                r"Cells show final pass rate; parentheses give $\Delta$ "
                r"from the round~0 baseline."
            )
        )
    else:
        pct_bit = r"Cells show the selected metric (\%)." if pct else r"Cells show the selected metric (raw)."
    return (
        f"Pair selection on \\texttt{{{ct}}} "
        f"(\\texttt{{{st_esc}}} variation style): final judge pass "
        f"rate after {round_word(rounds)} rewriter rounds, by "
        r"\textit{(judge, rewriter)} pair. "
        r"Rows are judges; columns are rewriters. "
        f"{pct_bit} Cells marked ``---'' are empirical work pending."
    )


def tex_table_label(stem: str, style: str) -> str:
    safe_stem = stem.replace("_", "-")
    safe_style = style.replace("_", "-")
    return f"tab:{safe_stem}-{safe_style}"


DASH_MARKERS = ("—", "—", "---")


def parse_base_tex(
    path: Path,
) -> Tuple[Dict[str, Dict[Tuple[str, str], str]], Dict[str, Tuple[str, str]]]:
    """Parse a previously-generated tex file.

    Returns: (cells_by_label, key_by_label). Cell text is taken verbatim;
    blank cells (``---``) are dropped. ``key_by_label`` maps each table
    label to its (stem, style) when a ``% table-key`` comment is present.
    """
    if not path or not path.exists():
        return {}, {}
    text = path.read_text()
    cells_by_label: Dict[str, Dict[Tuple[str, str], str]] = {}
    key_by_label: Dict[str, Tuple[str, str]] = {}
    # Iterate by tabular blocks; label/key comments sit just before \begin{tabular}.
    for tab_m in re.finditer(
        r"\\begin\{tabular\}.*?\\end\{tabular\}", text, re.DOTALL
    ):
        tab = tab_m.group(0)
        prefix = text[: tab_m.start()]
        label_m = None
        for m in re.finditer(r"\\label\{([^}]+)\}", prefix):
            label_m = m
        if not label_m:
            continue
        label = label_m.group(1)
        # Optional round-trip key in a comment ahead of this table.
        key_m = None
        for m in re.finditer(
            r"%\s*table-key:\s*stem=([^;\n]+);\s*style=([^\n]+)", prefix
        ):
            key_m = m
        if key_m:
            key_by_label[label] = (key_m.group(1).strip(), key_m.group(2).strip())
        hdr_m = re.search(r"\\textbf\{Judge\}\s*&([^\\\n]+)\\\\", tab)
        if not hdr_m:
            continue
        rw_cells = [c.strip() for c in hdr_m.group(1).split("&")]
        body_m = re.search(r"\\midrule(.*?)\\bottomrule", tab, re.DOTALL)
        if not body_m:
            body_m = re.search(r"\\hline(.*?)\\hline", tab, re.DOTALL)
            if not body_m:
                continue
        body = body_m.group(1)
        cells: Dict[Tuple[str, str], str] = {}
        for raw_row in body.split(r"\\"):
            row = raw_row.strip()
            if not row or row.startswith("%"):
                continue
            parts = [p.strip() for p in row.split("&")]
            if len(parts) < 2:
                continue
            judge_short = parts[0]
            for rw_short, cell in zip(rw_cells, parts[1:]):
                if cell and cell not in DASH_MARKERS:
                    cells[(judge_short, rw_short)] = cell
        if cells:
            cells_by_label[label] = cells
    return cells_by_label, key_by_label


def render_tex(
    judges,
    rewriters,
    matrix,
    stem: str,
    style: str,
    *,
    use_booktabs: bool,
    float_table: bool,
    rewriter_rounds: int,
    pct: bool,
    show_delta: bool,
):
    """Academic-style table: caption, two-row rewriter header (like paper template)."""
    ncol = len(rewriters)
    last_col = ncol + 1
    cols = "@{}l" + ("c" * ncol) + "@{}"

    caption = build_tex_table_caption(
        stem, style, rounds=rewriter_rounds, pct=pct, show_delta=show_delta
    )
    label = tex_table_label(stem, style)

    head_jcols = [tex_short_judge(j) for j in judges]
    head_rcols = [tex_short_rewriter(r) for r in rewriters]

    if use_booktabs:
        rule_top = r"\toprule"
        rule_mid = r"\midrule"
        rule_bot = r"\bottomrule"
        rw_rule = rf"\cmidrule(l){{2-{last_col}}}"
    else:
        rule_top = rule_mid = rule_bot = r"\hline"
        rw_rule = rf"\cline{{2-{last_col}}}"

    row0 = rf" & \multicolumn{{{ncol}}}{{c}}{{\textbf{{Rewriter}}}} \\"
    row1 = (
        r"\textbf{Judge} & " + " & ".join(head_rcols) + r" \\"
    )
    hdr = "\n".join([rule_top, row0, rw_rule, row1, rule_mid])

    dash_markers = ("\u2014", "—", "---")

    body_rows = []
    for j, j_disp in zip(judges, head_jcols):
        cells_raw = [matrix.get((j, r), "---") for r in rewriters]
        esc_cells = [
            "---" if c in dash_markers else tex_escape(c) for c in cells_raw
        ]
        body_rows.append(" & ".join([j_disp] + esc_cells) + r" \\")

    tabular_inner = "\n".join([hdr] + body_rows + [rule_bot])

    prelude = [
        "% Requires: \\usepackage{booktabs}"
        if use_booktabs
        else "% Uses: \\hline (no booktabs)."
    ]
    prelude.append("% Float: \\caption above tabular.")
    # Round-trip key so a later run with --base can recover (stem, style).
    prelude.append(f"% table-key: stem={stem}; style={style}")

    blob = "\\begin{tabular}{%s}\n%s\n\\end{tabular}" % (cols, tabular_inner)

    if float_table:
        blob = (
            "\\begin{table}[!ht]\n"
            "\\centering\n"
            "\\caption{%s}\n"
            "\\label{%s}\n"
            "\\small\n"
            "%s\n"
            "\\end{table}"
        ) % (caption, label, blob)
    else:
        blob = ("% %s -- %s\n" % (
            tex_escape(stem),
            tex_escape(style),
        )) + blob

    return "\n".join(prelude) + "\n" + blob + "\n"


EXCLUDE_FROM_COMBINED = {
    "azure/gpt-5.4",
    "openai/gpt-5.4-mini",
    "openai/gpt-5.4-mini-2026-03-17",
}


def is_opus_or_sonnet(model_id: str) -> bool:
    s = model_id.lower()
    return "opus" in s or "sonnet" in s


def render_tex_combined(
    stems,
    styles_by_stem,
    judges,
    rewriters,
    cells_by_stem_style,
    *,
    use_booktabs: bool,
    float_table: bool,
    rewriter_rounds: int,
    pct: bool,
    show_delta: bool,
):
    """One big table across all campaigns: rows = (campaign, style, judge),
    columns = rewriters.

    `cells_by_stem_style[(stem, style)][(judge, rewriter)] -> cell_str`
    (already formatted). Stems and their styles are emitted in the order
    given; empty groups are skipped.
    """
    ncol = len(rewriters)
    last_col = ncol + 3  # leftmost three columns are (campaign, style, judge)
    cols = "@{}lll" + ("c" * ncol) + "@{}"

    if show_delta:
        body_caption = (
            r"final judge pass rate after "
            f"{round_word(rewriter_rounds)} rewriter rounds, by "
            r"\textit{(campaign, variation style, judge, rewriter)} tuple. "
            r"Cells show final pass rate (\%); parentheses give $\Delta$ "
            r"from the round~0 baseline, in percentage points. "
            r"Cells marked ``---'' are empirical work pending."
        )
    else:
        body_caption = (
            r"selected metric per (campaign, variation style, judge, "
            r"rewriter) tuple. Cells marked ``---'' are empirical work "
            r"pending."
        )
    caption = "Pair selection across campaigns: " + body_caption
    label = "tab:all-combined"

    head_jcols = [tex_short_judge(j) for j in judges]
    head_rcols = [tex_short_rewriter(r) for r in rewriters]

    if use_booktabs:
        rule_top = r"\toprule"
        rule_mid = r"\midrule"
        rule_bot = r"\bottomrule"
        rw_rule = rf"\cmidrule(l){{4-{last_col}}}"
        style_rule = rf"\cmidrule(l){{2-{last_col}}}"
    else:
        rule_top = rule_mid = rule_bot = r"\hline"
        rw_rule = rf"\cline{{4-{last_col}}}"
        style_rule = rf"\cline{{2-{last_col}}}"

    row0 = rf" & & & \multicolumn{{{ncol}}}{{c}}{{\textbf{{Rewriter}}}} \\"
    row1 = (
        r"\textbf{Campaign} & \textbf{Style} & \textbf{Judge} & "
        + " & ".join(head_rcols) + r" \\"
    )
    hdr = "\n".join([rule_top, row0, rw_rule, row1, rule_mid])

    dash_markers = ("—", "—", "---")
    n_judges = len(judges)
    body_chunks = []
    for ci, stem in enumerate(stems):
        styles = styles_by_stem.get(stem, [])
        if not styles:
            continue
        camp_span = max(n_judges * len(styles), 1)
        camp_label = (
            rf"\multirow{{{camp_span}}}{{*}}{{\texttt{{"
            f"{tex_escape(campaign_title(stem))}"
            r"}}"
        )
        first_row_in_camp = True
        for si, style in enumerate(styles):
            matrix = cells_by_stem_style.get((stem, style), {})
            style_label = (
                rf"\multirow{{{n_judges}}}{{*}}{{\texttt{{"
                f"{tex_escape(style)}"
                r"}}"
            )
            for ji, (j, j_disp) in enumerate(zip(judges, head_jcols)):
                cells_raw = [matrix.get((j, r), "---") for r in rewriters]
                esc = ["---" if c in dash_markers else tex_escape(c) for c in cells_raw]
                left_camp = camp_label if first_row_in_camp else ""
                left_style = style_label if ji == 0 else ""
                body_chunks.append(
                    " & ".join([left_camp, left_style, j_disp] + esc) + r" \\"
                )
                first_row_in_camp = False
            if si != len(styles) - 1:
                body_chunks.append(style_rule)
        if ci != len(stems) - 1:
            body_chunks.append(rule_mid)

    tabular_inner = "\n".join([hdr] + body_chunks + [rule_bot])

    prelude = []
    if use_booktabs:
        prelude.append(r"% Requires: \usepackage{booktabs} \usepackage{multirow}")
    else:
        prelude.append(r"% Requires: \usepackage{multirow}")
    prelude.append("% Float: \\caption above tabular.")
    prelude.append("% table-key: combined-all=1")

    blob = "\\begin{tabular}{%s}\n%s\n\\end{tabular}" % (cols, tabular_inner)
    if float_table:
        blob = (
            "\\begin{table}[!ht]\n"
            "\\centering\n"
            "\\caption{%s}\n"
            "\\label{%s}\n"
            "\\small\n"
            "%s\n"
            "\\end{table}"
        ) % (caption, label, blob)
    else:
        blob = "% all-combined\n" + blob

    return "\n".join(prelude) + "\n" + blob + "\n"


def render_md_combined(stems, styles_by_stem, judges, rewriters,
                       cells_by_stem_style):
    head = "| Campaign | Style | Judge | " + " | ".join(rewriters) + " |"
    sep = "|" + "---|" * (len(rewriters) + 3)
    rows = ["### All campaigns (combined)", "", head, sep]
    for stem in stems:
        first_row_in_camp = True
        for style in styles_by_stem.get(stem, []):
            matrix = cells_by_stem_style.get((stem, style), {})
            for ji, j in enumerate(judges):
                left_camp = campaign_title(stem) if first_row_in_camp else ""
                left_style = style if ji == 0 else ""
                cells = [matrix.get((j, r), "—") for r in rewriters]
                rows.append(
                    f"| {left_camp} | {left_style} | {j} | "
                    + " | ".join(cells) + " |"
                )
                first_row_in_camp = False
    return "\n".join(rows) + "\n"


def render_csv_combined(stems, styles_by_stem, judges, rewriters,
                        cells_by_stem_style):
    out = ["# All campaigns (combined)"]
    out.append("campaign,style,judge," + ",".join(rewriters))
    for stem in stems:
        for style in styles_by_stem.get(stem, []):
            matrix = cells_by_stem_style.get((stem, style), {})
            for j in judges:
                cells = [matrix.get((j, r), "") for r in rewriters]
                out.append(f"{stem},{style},{j}," + ",".join(cells))
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs-root", default="runs", type=Path)
    ap.add_argument(
        "--judges",
        default=(
            "meta-llama/llama-guard-4-12b,anthropic/claude-sonnet-4-6,"
            "anthropic/claude-opus-4-6,openai/gpt-5.4-mini-2026-03-17"
        ),
        help="Comma-separated judge model ids (defines row order).",
    )
    ap.add_argument(
        "--rewriters",
        default=(
            "anthropic/claude-sonnet-4-6,anthropic/claude-opus-4-6,"
            "openai/gpt-5.4-mini-2026-03-17,azure/gpt-5.4,deepseek/deepseek-v4-flash"
        ),
        help="Comma-separated rewriter model ids (defines column order).",
    )
    ap.add_argument("--metric", choices=["final", "max", "first"], default="final")
    ap.add_argument("--format", choices=["md", "tex", "csv"], default="md")
    ap.add_argument(
        "--no-delta",
        action="store_true",
        help="Single metric only (--metric); no final(Δ) vs round-0 baseline.",
    )
    ap.add_argument(
        "--show-baseline-in-cell",
        action="store_true",
        help="Append [base …] after final(Δ) in each cell.",
    )
    ap.add_argument(
        "--tex-booktabs",
        dest="tex_booktabs",
        action="store_true",
        default=True,
        help="Use booktabs rules in LaTeX (default: on).",
    )
    ap.add_argument(
        "--tex-no-booktabs",
        action="store_true",
        help=r"Use \hline instead of booktabs (no extra package).",
    )
    ap.add_argument(
        "--tex-tabular-only",
        action="store_true",
        help=r"LaTeX: omit table float (\begin{table}); output only tabular + comments.",
    )
    ap.add_argument(
        "--tex-space-delta",
        action="store_true",
        help=r"Cells: ``90.0 (+3.0)'' instead of ``90.0(+3.0)''.",
    )
    ap.add_argument(
        "--rewrite-rounds",
        type=int,
        default=10,
        help="Mention N rewriter rounds in the LaTeX caption (default 10).",
    )
    ap.add_argument("--campaigns", default=None, help="Restrict to these dataset stems (csv).")
    ap.add_argument("--styles", default=None, help="Restrict to these variation styles (csv).")
    ap.add_argument("--no-pct", action="store_true", help="Show raw 0..1 instead of percent.")
    ap.add_argument("--places", type=int, default=1, help="Decimal places for numbers.")
    ap.add_argument("--out", type=Path, default=None, help="Write to file (default: stdout).")
    ap.add_argument(
        "--base",
        type=Path,
        default=None,
        help=(
            "Path to a previously-generated .tex file. Cells with real "
            "numbers in the base are preserved; new runs only fill cells "
            "that the base leaves blank (---)."
        ),
    )
    ap.add_argument(
        "--combined",
        action="store_true",
        help=(
            "Emit one big table per campaign with rows = (style, judge) and "
            "columns = rewriter, instead of one small table per (campaign, "
            "style). Excludes azure/gpt-5.4 and openai/gpt-5.4-mini[-*] from "
            "both rows and columns by default; pass --judges/--rewriters to "
            "override."
        ),
    )
    args = ap.parse_args()

    show_delta = not args.no_delta
    use_booktabs = args.tex_booktabs and not args.tex_no_booktabs

    judges = [j.strip() for j in args.judges.split(",") if j.strip()]
    rewriters = [r.strip() for r in args.rewriters.split(",") if r.strip()]
    if args.combined:
        # Drop gpt-5.4 family from rows AND columns when no explicit override
        # would otherwise reduce the table; users can re-add via --judges/--rewriters.
        judges = [j for j in judges if j not in EXCLUDE_FROM_COMBINED]
        rewriters = [r for r in rewriters if r not in EXCLUDE_FROM_COMBINED]
    judge_slugs = {SLUG(j): j for j in judges}
    rewriter_slugs = {SLUG(r): r for r in rewriters}

    pick_campaigns = set(args.campaigns.split(",")) if args.campaigns else None
    pick_styles = set(args.styles.split(",")) if args.styles else None

    grid: dict = defaultdict(dict)

    for d in sorted(args.runs_root.iterdir() if args.runs_root.exists() else []):
        if not d.is_dir():
            continue
        meta = parse_run_dir(d.name)
        if not meta:
            continue
        if pick_campaigns and meta["stem"] not in pick_campaigns:
            continue
        if pick_styles and meta["style"] not in pick_styles:
            continue
        j = judge_slugs.get(meta["judge_slug"])
        r = rewriter_slugs.get(meta.get("rewriter_slug", ""))
        if not j or not r:
            continue
        traj_path = d / "run_trajectory.json"
        if show_delta:
            b, fin, delta = baseline_final_delta(traj_path)
            payload = (meta["ts"], (b, fin, delta))
        else:
            m = metric_from_trajectory(traj_path, args.metric)
            payload = (meta["ts"], m)
        key = (meta["stem"], meta["style"])
        cell = (j, r)
        prev = grid[key].get(cell)
        if prev is None or meta["ts"] > prev[0]:
            grid[key][cell] = payload

    if args.base:
        base_data, base_keys = parse_base_tex(args.base)
        # Seed empty entries so base-only tables are still emitted when
        # the new run lacks matching log dirs.
        for label, key in base_keys.items():
            grid.setdefault(key, {})
    else:
        base_data, base_keys = {}, {}

    chunks = []
    pct = not args.no_pct
    places = args.places
    missing_cell = "---" if args.format == "tex" else "\u2014"

    cell_strs_by_key: Dict[Tuple[str, str], Dict[Tuple[str, str], str]] = {}
    for (stem, style) in sorted(grid):
        cell_strs = {}
        for k, v in grid[(stem, style)].items():
            if show_delta:
                b, fin, delta = v[1]
                cell_strs[k] = fmt_cell_with_delta(
                    b,
                    fin,
                    delta,
                    pct=pct,
                    places=places,
                    show_baseline=args.show_baseline_in_cell,
                    missing=missing_cell,
                    space_before_delta=args.tex_space_delta,
                )
            else:
                cell_strs[k] = fmt_cell(
                    v[1], pct=pct, places=places, missing=missing_cell
                )

        if base_data:
            base_cells = base_data.get(tex_table_label(stem, style), {})
            if base_cells:
                # Ensure every (judge, rewriter) intersection is considered,
                # not just ones the new run produced \u2014 base values must
                # survive even when there is no fresh run dir.
                for j in judges:
                    for r in rewriters:
                        bv = base_cells.get((tex_short_judge(j), tex_short_rewriter(r)))
                        if bv is not None:
                            cell_strs[(j, r)] = bv
        cell_strs_by_key[(stem, style)] = cell_strs

    if args.combined:
        # Force opus/sonnet rewriter columns to "empirical work pending"
        # ("---"); judge values are left intact.
        opus_sonnet_rewriters = [r for r in rewriters if is_opus_or_sonnet(r)]
        for cs in cell_strs_by_key.values():
            for j in judges:
                for r in opus_sonnet_rewriters:
                    cs[(j, r)] = missing_cell

        by_stem: Dict[str, List[str]] = defaultdict(list)
        for (stem, style) in cell_strs_by_key:
            by_stem[stem].append(style)
        stems = sorted(by_stem)
        styles_by_stem = {s: sorted(by_stem[s]) for s in stems}

        if args.format == "md":
            chunks.append(render_md_combined(
                stems, styles_by_stem, judges, rewriters, cell_strs_by_key))
        elif args.format == "tex":
            chunks.append(render_tex_combined(
                stems, styles_by_stem, judges, rewriters, cell_strs_by_key,
                use_booktabs=use_booktabs,
                float_table=not args.tex_tabular_only,
                rewriter_rounds=args.rewrite_rounds,
                pct=pct,
                show_delta=show_delta,
            ))
        else:
            chunks.append(render_csv_combined(
                stems, styles_by_stem, judges, rewriters, cell_strs_by_key))
    else:
        for (stem, style), cell_strs in cell_strs_by_key.items():
            title = f"{stem} — style: {style}"
            if show_delta:
                title += " — final pass_rate (Δ vs round-0 baseline)"
                title += " (raw)" if not pct else " (%)"
            else:
                title += f" — metric: {args.metric}" + ("" if pct else " (raw)")
                if pct:
                    title += " (%)"

            if args.format == "md":
                chunks.append(render_md(judges, rewriters, cell_strs, title))
            elif args.format == "tex":
                chunks.append(
                    render_tex(
                        judges,
                        rewriters,
                        cell_strs,
                        stem,
                        style,
                        use_booktabs=use_booktabs,
                        float_table=not args.tex_tabular_only,
                        rewriter_rounds=args.rewrite_rounds,
                        pct=pct,
                        show_delta=show_delta,
                    )
                )
            else:
                chunks.append(render_csv(judges, rewriters, cell_strs, title))

    if chunks:
        text = "\n".join(chunks)
    else:
        text = ("% no runs matched filters.\n" if args.format == "tex"
                else "# no runs found\n")
    if args.out:
        args.out.write_text(text)
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()
