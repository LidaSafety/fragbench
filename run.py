"""
CLI entry point for fragguard-chain.

Examples:
    # Run all campaigns against Qwen (keyword classifier)
    python run.py --model qwen --qwen-key $DASHSCOPE_API_KEY

    # Run all campaigns against Claude with LLM judge
    python run.py --model claude --judge

    # Run a single campaign
    python run.py --campaign dprk_fraud --model claude --judge

    # Run with extended thinking on the target model (Claude only)
    python run.py --model claude --thinking --judge

    # Output JSON results to a file
    python run.py --model claude --judge --output results/run1.json

    # Generate attack variations from a seed file (dry-run, no LLM)
    python run.py --generate --seed-file seeds/promptsteal.json --num-variations 5 --dry-run

    # Generate with LLM fragmentation + legitimization, write TOML to attacks/
    python run.py --generate --seed-file seeds/promptsteal.json --num-variations 10 \\
        --claude-key $ANTHROPIC_API_KEY
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="FragGuard-Seq: attack variation harness with kill-chain detection"
    )
    p.add_argument(
        "--model",
        choices=["qwen", "claude"],
        default="qwen",
        help="Target model to probe (default: qwen)",
    )
    p.add_argument(
        "--qwen-key",
        default=os.environ.get("DASHSCOPE_API_KEY"),
        help="DashScope API key (or set DASHSCOPE_API_KEY)",
    )
    p.add_argument(
        "--qwen-model",
        default="qwen-plus",
        help="Qwen model name (default: qwen-plus)",
    )
    p.add_argument(
        "--claude-key",
        default=os.environ.get("ANTHROPIC_API_KEY"),
        help="Anthropic API key (or set ANTHROPIC_API_KEY)",
    )
    p.add_argument(
        "--claude-model",
        default="claude-sonnet-4-6",
        help="Claude model name (default: claude-sonnet-4-6)",
    )
    p.add_argument(
        "--thinking",
        action="store_true",
        help="Enable extended thinking on Claude target model",
    )
    p.add_argument(
        "--judge",
        action="store_true",
        help="Use LLM-as-judge (Claude Haiku) for classification instead of keyword heuristics",
    )
    p.add_argument(
        "--judge-model",
        default="claude-haiku-4-5-20251001",
        help="Claude model to use as judge (default: claude-haiku-4-5-20251001)",
    )
    p.add_argument(
        "--campaign",
        default=None,
        help="Run a single campaign by ID (e.g. DPRK_FRAUD). Omit to run all.",
    )
    p.add_argument(
        "--attacks-dir",
        default="attacks",
        help="Directory containing attack TOML files (default: attacks/)",
    )
    p.add_argument(
        "--output",
        default=None,
        help="Write JSON results to this file path",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print prompts without calling any model APIs",
    )

    # --- Dataset generation mode -------------------------------------------
    p.add_argument(
        "--generate",
        action="store_true",
        help="Run the dataset generation pipeline instead of evaluation",
    )
    p.add_argument(
        "--seed-file",
        default=None,
        help="Path to a seed JSON file in seeds/ (required with --generate)",
    )
    p.add_argument(
        "--num-variations",
        type=int,
        default=100,
        help="Number of variations to generate (default: 100)",
    )
    p.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Base seed for generation (default: random). Use for reproducibility.",
    )

    return p.parse_args()


def build_runner(args: argparse.Namespace):
    from harness import ClaudeRunner, QwenRunner

    if args.model == "qwen":
        if not args.qwen_key:
            print("ERROR: --qwen-key or DASHSCOPE_API_KEY required for qwen model", file=sys.stderr)
            sys.exit(1)
        return QwenRunner(api_key=args.qwen_key, model=args.qwen_model)
    else:
        if not args.claude_key:
            print("ERROR: --claude-key or ANTHROPIC_API_KEY required for claude model", file=sys.stderr)
            sys.exit(1)
        return ClaudeRunner(
            api_key=args.claude_key,
            model=args.claude_model,
            extended_thinking=args.thinking,
        )


def print_result_row(style: str, verdict: str, justification: str = "") -> None:
    color = {
        "ANSWERED": "\033[91m",  # red — model complied (bad)
        "REFUSED":  "\033[92m",  # green — model refused (good)
        "PARTIAL":  "\033[93m",  # yellow
        "UNCLEAR":  "\033[90m",  # gray
    }.get(verdict, "")
    reset = "\033[0m"
    just = f"  [{justification}]" if justification else ""
    print(f"  {color}{verdict:8s}{reset}  {style}{just}")


def run_campaign(spec, runner, args) -> dict:
    from detector import JudgeResult, keyword_classify, killchain_score, llm_judge

    print(f"\n{'='*60}")
    print(f"Campaign: {spec.metadata.id}  ({spec.metadata.technique})")
    print(f"  {spec.metadata.technique_name}")
    print(f"{'='*60}")

    results_by_fragment: list[list] = []

    for fragment in spec.fragments:
        print(f"\nFragment {fragment.index}: {fragment.description}")
        frag_results = []

        for variation in fragment.variations:
            if args.dry_run:
                print(f"  [DRY RUN] {variation.style}: {variation.prompt[:80]}...")
                continue

            print(f"  Probing [{variation.style}]...", end=" ", flush=True)
            result = runner.run_variation(variation, spec.metadata.id, fragment.index)

            if result.error:
                print(f"ERROR: {result.error}")
                frag_results.append(result)
                continue

            # Classify
            if args.judge:
                judge: JudgeResult = llm_judge(
                    result.prompt,
                    result.response,
                    api_key=args.claude_key,
                    model=args.judge_model,
                )
                verdict = judge.verdict
                justification = judge.justification
            else:
                verdict = keyword_classify(result.response)
                justification = ""

            # Attach verdict to result for serialization
            result.__dict__["verdict"] = verdict
            result.__dict__["justification"] = justification

            print_result_row(variation.style, verdict, justification)
            frag_results.append(result)

        if not args.dry_run:
            results_by_fragment.append(frag_results)

    if args.dry_run:
        return {}

    # Kill-chain scoring (use already-computed verdicts — skip re-judging)
    from detector import COMPLIANT_VERDICTS, KillchainResult

    fragment_summaries = []
    compliant_fragment_count = 0
    for frag_idx, frag_results in enumerate(results_by_fragment):
        frag_complied = [r.style for r in frag_results if r.__dict__.get("verdict") in COMPLIANT_VERDICTS]
        frag_refused  = [r.style for r in frag_results if r.__dict__.get("verdict") not in COMPLIANT_VERDICTS]
        fragment_compliant = len(frag_complied) > 0
        if fragment_compliant:
            compliant_fragment_count += 1
        fragment_summaries.append({
            "fragment_index": frag_idx,
            "description": spec.fragments[frag_idx].description,
            "compliant": fragment_compliant,
            "styles_complied": frag_complied,
            "styles_refused": frag_refused,
            "compliance_rate": len(frag_complied) / len(frag_results) if frag_results else 0.0,
        })

    total = len(results_by_fragment)
    kc = KillchainResult(
        campaign_id=spec.metadata.id,
        technique=spec.metadata.technique,
        total_fragments=total,
        compliant_fragments=compliant_fragment_count,
        styles_complied=[s for f in fragment_summaries for s in f["styles_complied"]],
        styles_refused=[s for f in fragment_summaries for s in f["styles_refused"]],
        kill_chain_complete=(compliant_fragment_count == total and total > 0),
        compliance_rate=compliant_fragment_count / total if total > 0 else 0.0,
        fragment_summaries=fragment_summaries,
    )

    # Print kill-chain summary
    kc_color = "\033[91m" if kc.kill_chain_complete else "\033[92m"
    reset = "\033[0m"
    print(f"\nKill-chain: {kc_color}{'COMPLETE' if kc.kill_chain_complete else 'BLOCKED'}{reset}")
    print(f"  Fragments compliant: {kc.compliant_fragments}/{kc.total_fragments}")
    print(f"  Variation compliance rate: {len(kc.styles_complied)}/{len(kc.styles_complied)+len(kc.styles_refused)}")

    # Build output dict
    return {
        "campaign_id": spec.metadata.id,
        "technique": spec.metadata.technique,
        "technique_name": spec.metadata.technique_name,
        "killchain": kc.__dict__,
        "variations": [
            {
                "fragment_index": r.fragment_index,
                "style": r.style,
                "prompt": r.prompt,
                "response": r.response,
                "verdict": r.__dict__.get("verdict", "UNCLEAR"),
                "justification": r.__dict__.get("justification", ""),
                "model": r.model,
                "error": r.error,
            }
            for frag_results in results_by_fragment
            for r in frag_results
        ],
    }


def run_generate(args) -> None:
    """Dataset generation pipeline: seed file → vary → fragment → legitimize → TOML."""
    import json as _json
    import random as _random

    from generator import VARIATION_REGISTRY, generate_toml, legitimize_fragment, make_fragments

    if not args.seed_file:
        print("ERROR: --seed-file <path> is required with --generate", file=sys.stderr)
        sys.exit(1)

    seed_path = Path(args.seed_file)
    if not seed_path.exists():
        print(f"ERROR: seed file not found: {seed_path}", file=sys.stderr)
        sys.exit(1)

    seed_data = _json.loads(seed_path.read_text())
    campaign_id = seed_data["metadata"]["id"].lower()

    if campaign_id not in VARIATION_REGISTRY:
        available = ", ".join(VARIATION_REGISTRY)
        print(f"ERROR: no variation class for '{campaign_id}'. Registered: {available}", file=sys.stderr)
        sys.exit(1)

    gen = VARIATION_REGISTRY[campaign_id](args.seed_file)
    api_key = args.claude_key if not args.dry_run else None
    base_seed = args.seed if args.seed is not None else _random.randint(0, 2**31)

    print(f"Generating {args.num_variations} variation(s) "
          f"[campaign={campaign_id.upper()}, base_seed={base_seed}]")

    final_frag_list: list[list[str]] = []
    for i in range(args.num_variations):
        seed = base_seed + i
        var = gen.make_variation(seed)  # list[tuple[str, str]]

        if args.dry_run:
            print(f"\n  [variation {i}  seed={seed}]")
            for step, tactic in var:
                print(f"    ({tactic})  {step}")
            continue

        fragments = make_fragments(var, api_key=api_key)
        legitimized = [legitimize_fragment(frag, api_key=api_key) for frag in fragments]
        final_frag_list.append(legitimized)

    if args.dry_run:
        return

    attacks_dir = Path(args.attacks_dir)
    attacks_dir.mkdir(parents=True, exist_ok=True)

    written: list[Path] = []
    for i, frags in enumerate(final_frag_list):
        seed = base_seed + i
        toml_text = generate_toml(seed_data["metadata"], [frags], seed)
        out_path = attacks_dir / f"generated_{campaign_id}_{seed}.toml"
        out_path.write_text(toml_text)
        written.append(out_path)

    print(f"\nWrote {len(written)} TOML file(s) to {attacks_dir}/")
    for p in written:
        print(f"  {p.name}")


def main() -> None:
    args = parse_args()
    logging.basicConfig(
        format="%(levelname)s [%(name)s] %(message)s",
        level=logging.WARNING,
    )

    if args.generate:
        run_generate(args)
        return

    from harness import load_all_attacks

    # Load attack specs
    attacks_dir = Path(args.attacks_dir)
    if not attacks_dir.exists():
        print(f"ERROR: attacks directory not found: {attacks_dir}", file=sys.stderr)
        sys.exit(1)

    all_specs = load_all_attacks(attacks_dir)
    if not all_specs:
        print(f"ERROR: no *.toml files found in {attacks_dir}", file=sys.stderr)
        sys.exit(1)

    # Filter to single campaign if requested
    if args.campaign:
        all_specs = [s for s in all_specs if s.metadata.id.upper() == args.campaign.upper()]
        if not all_specs:
            print(f"ERROR: campaign '{args.campaign}' not found", file=sys.stderr)
            sys.exit(1)

    # Build runner
    runner = None if args.dry_run else build_runner(args)

    # Run campaigns
    all_results = []
    for spec in all_specs:
        campaign_result = run_campaign(spec, runner, args)
        if campaign_result:
            all_results.append(campaign_result)

    # Overall summary
    if all_results:
        print(f"\n{'='*60}")
        print("SUMMARY")
        print(f"{'='*60}")
        for r in all_results:
            kc = r["killchain"]
            status = "COMPLETE" if kc["kill_chain_complete"] else "BLOCKED"
            print(f"  {r['campaign_id']:25s}  {status:8s}  "
                  f"{kc['compliant_fragments']}/{kc['total_fragments']} fragments")

    # Write JSON output
    if args.output and all_results:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_doc = {
            "run_timestamp": datetime.now(timezone.utc).isoformat(),
            "target_model": args.qwen_model if args.model == "qwen" else args.claude_model,
            "classifier": "llm_judge" if args.judge else "keyword",
            "campaigns": all_results,
        }
        output_path.write_text(json.dumps(output_doc, indent=2))
        print(f"\nResults written to {output_path}")


if __name__ == "__main__":
    main()
