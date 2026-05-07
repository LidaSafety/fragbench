#!/usr/bin/env bash
# run_grid.sh — sweep (dataset × variation-style × judge × rewriter)
set -euo pipefail
export PYTHONUNBUFFERED=1   # flush python prints line-by-line through tee

DATASETS_DEFAULT=(
  "dataset/dprk_fraud_llm.json"
  "dataset/promptsteal_llm.json"
  "dataset/quietvault_llm.json"
)
STYLES_DEFAULT=(command_form compliance_audit direct educational helpdesk sysadmin)
REWRITERS_DEFAULT=(
  "anthropic/claude-sonnet-4-6"
  "anthropic/claude-opus-4-6"
  "openai/gpt-5.4-mini-2026-03-17"
  "openai/gpt-5.4"
  "deepseek/deepseek-v4-flash"
)
JUDGES_DEFAULT=(
  "meta-llama/llama-guard-4-12b"
  "anthropic/claude-sonnet-4-6"
  "anthropic/claude-opus-4-6"
  "openai/gpt-5.4-mini-2026-03-17"
)

DATASETS=("${DATASETS_DEFAULT[@]}")
STYLES=("${STYLES_DEFAULT[@]}")
REWRITERS=("${REWRITERS_DEFAULT[@]}")
JUDGES=("${JUDGES_DEFAULT[@]}")
MODE="${MODE:-rl}"
# `auto` → infer per model (anthropic/* -> anthropic, else openrouter).
# Set to a concrete backend name to force it for every row.
JUDGE_BACKEND="${JUDGE_BACKEND:-auto}"
REWRITER_BACKEND="${REWRITER_BACKEND:-auto}"
EXTRA_ARGS=()
DRY_RUN=0
CONTINUE_ON_ERROR=1

usage() {
  cat <<'EOF'
Usage: run_grid.sh [options]
  --datasets=a.json,b.json     override dataset paths
  --styles=direct,helpdesk     override variation styles
  --rewriters=m1,m2            override rewriter models
  --judges=m1,m2               override judge models
  --mode=rl|judge              default: rl
  --judge-backend=NAME         auto (default) | anthropic | openrouter | ...
  --rewriter-backend=NAME      auto (default) | anthropic | openrouter | ...
  --extra="--max-samples 10 --rounds 3"   passed verbatim
  --stop-on-error              abort on first failure (default: keep going)
  --dry-run                    print commands, do not execute
  -h | --help

Backend auto-routing (when backend is "auto"):
  model starts with anthropic/  -> --*-backend anthropic
  anything else                 -> --*-backend openrouter

Env:
  ANTHROPIC_API_KEY  required when any row resolves to backend=anthropic
  OPENROUTER_API_KEY required when any row resolves to backend=openrouter
EOF
}

infer_backend() {
  # $1 = model id, $2 = configured backend (auto | <forced>)
  if [[ "$2" != "auto" ]]; then echo "$2"; return; fi
  case "$1" in
    anthropic/*) echo "anthropic" ;;
    *)           echo "openrouter" ;;
  esac
}

split_csv() { local IFS=','; read -r -a __out <<<"$1"; printf '%s\n' "${__out[@]}"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --datasets=*)  DATASETS=();  while IFS= read -r _i; do DATASETS+=("$_i");  done < <(split_csv "${1#*=}") ;;
    --styles=*)    STYLES=();    while IFS= read -r _i; do STYLES+=("$_i");    done < <(split_csv "${1#*=}") ;;
    --rewriters=*) REWRITERS=(); while IFS= read -r _i; do REWRITERS+=("$_i"); done < <(split_csv "${1#*=}") ;;
    --judges=*)    JUDGES=();    while IFS= read -r _i; do JUDGES+=("$_i");    done < <(split_csv "${1#*=}") ;;
    --mode=*)             MODE="${1#*=}" ;;
    --judge-backend=*)    JUDGE_BACKEND="${1#*=}" ;;
    --rewriter-backend=*) REWRITER_BACKEND="${1#*=}" ;;
    --extra=*)            read -r -a EXTRA_ARGS <<<"${1#*=}" ;;
    --stop-on-error)      CONTINUE_ON_ERROR=0 ;;
    --dry-run)            DRY_RUN=1 ;;
    -h|--help)            usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage; exit 2 ;;
  esac
  shift
done

need_anthropic=0; need_openrouter=0
for j in "${JUDGES[@]}";    do b=$(infer_backend "$j" "$JUDGE_BACKEND")
  [[ "$b" == "anthropic"  ]] && need_anthropic=1
  [[ "$b" == "openrouter" ]] && need_openrouter=1
done
for r in "${REWRITERS[@]}"; do b=$(infer_backend "$r" "$REWRITER_BACKEND")
  [[ "$b" == "anthropic"  ]] && need_anthropic=1
  [[ "$b" == "openrouter" ]] && need_openrouter=1
done
if [[ "$need_anthropic"  == "1" && -z "${ANTHROPIC_API_KEY:-}"  ]]; then
  echo "ERROR: ANTHROPIC_API_KEY is not set (some rows resolve to backend=anthropic)." >&2; exit 1
fi
if [[ "$need_openrouter" == "1" && -z "${OPENROUTER_API_KEY:-}" ]]; then
  echo "ERROR: OPENROUTER_API_KEY is not set (some rows resolve to backend=openrouter)." >&2; exit 1
fi

mkdir -p logs
total=$(( ${#DATASETS[@]} * ${#STYLES[@]} * ${#JUDGES[@]} * ${#REWRITERS[@]} ))
i=0; failed=0
echo "Planned runs: $total"

for ds in "${DATASETS[@]}"; do
  stem=$(basename "$ds" .json)
  for style in "${STYLES[@]}"; do
    for judge in "${JUDGES[@]}"; do
      for rewriter in "${REWRITERS[@]}"; do
        i=$((i+1))
        jb=$(infer_backend "$judge"    "$JUDGE_BACKEND")
        rb=$(infer_backend "$rewriter" "$REWRITER_BACKEND")
        tag="${stem}__vs-${style}__J-${judge//\//_}__R-${rewriter//\//_}"
        log="logs/${tag}.log"
        echo "[$i/$total] $tag (judge=$jb, rewriter=$rb)"
        if [ -f "$log" ] && grep -q 'SUMMARY' && ! grep -qE 'HTTP Error 4|Error code: 4' "$log"; then
          echo "  skip: prior run clean"
          continue
        fi
        rm -f "$log"
        cmd=( python -u fragbench_dataset_generator/fragbench_pack/fragbench_generated_rl.py
              --mode "$MODE"
              --variation-style "$style"
              --judge-backend    "$jb" --judge-model    "$judge"
              --rewriter-backend "$rb" --rewriter-model "$rewriter"
              --input "$ds" )
        [[ ${#EXTRA_ARGS[@]} -gt 0 ]] && cmd+=("${EXTRA_ARGS[@]}")
        if [[ "$DRY_RUN" == "1" ]]; then
          printf '  + %q ' "${cmd[@]}"; echo; continue
        fi
        { time "${cmd[@]}"; } 2>&1 | tee "$log"; _rc=${PIPESTATUS[0]}
        if [[ $_rc -ne 0 ]]; then
          failed=$((failed+1))
          echo "  FAILED (exit $_rc) -> $log"
          [[ "$CONTINUE_ON_ERROR" == "0" ]] && exit 1
        fi
      done
    done
  done
done

echo "Done. failed=$failed/$total"
