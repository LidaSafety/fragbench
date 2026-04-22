#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/.." && pwd)"
cd "$repo_root"

usage() {
  cat <<'EOF'
Batch-generate attack TOMLs for every seed JSON.

Usage:
  scripts/generate_all_seeds.sh [options] [-- <extra run.py args>]

Options:
  -n, --num-variations <int>  Variations per seed (default: 100)
  -s, --seeds-dir <path>      Seed directory (default: seeds)
  -o, --output-base-dir <path>
                              Parent dir for fresh batch output dir
                              (default: attacks/batches)
      --fragment              Enable fragmentation
      --stylize               Enable style generation
      --styles <csv>          Comma-separated styles, implies --stylize
      --legitimize            Enable legitimization
      --gen-backend <name>    Generation backend, e.g. anthropic or openrouter
      --gen-model <id>        Generation model id
      --gen-base-url <url>    OpenAI-compatible base URL for generation
  -h, --help                  Show this help

Behavior:
  - Creates a fresh output directory for each run.
  - Runs current generation pipeline via run.py --generate.
  - Writes all generated TOMLs into that directory via --attacks-dir.
  - Continues across seed files and exits non-zero if any seed fails.
  - By default this runs plain generation only; optional rewrite steps can be
    enabled with the flags above.

Examples:
  scripts/generate_all_seeds.sh -n 5
  scripts/generate_all_seeds.sh -n 1 --fragment --stylize --styles direct,helpdesk --legitimize
  scripts/generate_all_seeds.sh -- --dry-run
EOF
}

num_variations=100
seeds_dir="seeds"
output_base_dir="attacks/batches"
fragment=0
stylize=0
legitimize=0
styles=""
gen_backend=""
gen_model=""
gen_base_url=""
extra_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--num-variations)
      [[ $# -ge 2 ]] || { echo "ERROR: $1 requires a value" >&2; exit 1; }
      num_variations="$2"
      shift 2
      ;;
    -s|--seeds-dir)
      [[ $# -ge 2 ]] || { echo "ERROR: $1 requires a value" >&2; exit 1; }
      seeds_dir="$2"
      shift 2
      ;;
    -o|--output-base-dir)
      [[ $# -ge 2 ]] || { echo "ERROR: $1 requires a value" >&2; exit 1; }
      output_base_dir="$2"
      shift 2
      ;;
    --fragment)
      fragment=1
      shift
      ;;
    --stylize)
      stylize=1
      shift
      ;;
    --styles)
      [[ $# -ge 2 ]] || { echo "ERROR: $1 requires a value" >&2; exit 1; }
      styles="$2"
      stylize=1
      shift 2
      ;;
    --legitimize)
      legitimize=1
      shift
      ;;
    --gen-backend)
      [[ $# -ge 2 ]] || { echo "ERROR: $1 requires a value" >&2; exit 1; }
      gen_backend="$2"
      shift 2
      ;;
    --gen-model)
      [[ $# -ge 2 ]] || { echo "ERROR: $1 requires a value" >&2; exit 1; }
      gen_model="$2"
      shift 2
      ;;
    --gen-base-url)
      [[ $# -ge 2 ]] || { echo "ERROR: $1 requires a value" >&2; exit 1; }
      gen_base_url="$2"
      shift 2
      ;;
    --)
      shift
      extra_args=("$@")
      break
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if ! [[ "$num_variations" =~ ^[0-9]+$ ]] || (( num_variations <= 0 )); then
  echo "ERROR: --num-variations must be a positive integer" >&2
  exit 1
fi

if ! command -v uv >/dev/null 2>&1; then
  echo "ERROR: uv is not installed or not on PATH." >&2
  echo "Install uv: https://docs.astral.sh/uv/getting-started/installation/" >&2
  exit 1
fi

if [[ ! -d "$seeds_dir" ]]; then
  echo "ERROR: seeds directory not found: $seeds_dir" >&2
  exit 1
fi

shopt -s nullglob
seed_files=("$seeds_dir"/*.json)
shopt -u nullglob

if (( ${#seed_files[@]} == 0 )); then
  echo "ERROR: no seed JSON files found in $seeds_dir" >&2
  exit 1
fi

mkdir -p "$output_base_dir"
run_stamp="$(date -u +%Y%m%d_%H%M%S)"
output_dir="$(mktemp -d "${output_base_dir%/}/generated_${run_stamp}_XXXXXX")"

echo "Seeds found      : ${#seed_files[@]}"
echo "Num variations   : $num_variations"
echo "Batch output dir : $output_dir"
echo "Fragment         : $fragment"
echo "Stylize          : $stylize"
echo "Legitimize       : $legitimize"
if [[ -n "$styles" ]]; then
  echo "Styles           : $styles"
fi
if [[ -n "$gen_backend" ]]; then
  echo "Gen backend      : $gen_backend"
fi
if [[ -n "$gen_model" ]]; then
  echo "Gen model        : $gen_model"
fi
echo

failures=()

for seed_file in "${seed_files[@]}"; do
  echo "==> Generating from $seed_file"

  cmd=(
    uv run python run.py
    --generate
    --seed-file "$seed_file"
    --num-variations "$num_variations"
    --attacks-dir "$output_dir"
  )

  if (( fragment )); then
    cmd+=(--fragment)
  fi
  if (( stylize )); then
    cmd+=(--stylize)
  fi
  if [[ -n "$styles" ]]; then
    cmd+=(--styles "$styles")
  fi
  if (( legitimize )); then
    cmd+=(--legitimize)
  fi
  if [[ -n "$gen_backend" ]]; then
    cmd+=(--gen-backend "$gen_backend")
  fi
  if [[ -n "$gen_model" ]]; then
    cmd+=(--gen-model "$gen_model")
  fi
  if [[ -n "$gen_base_url" ]]; then
    cmd+=(--gen-base-url "$gen_base_url")
  fi
  if (( ${#extra_args[@]} > 0 )); then
    cmd+=("${extra_args[@]}")
  fi

  if "${cmd[@]}"; then
    echo "    OK: $seed_file"
  else
    echo "    FAIL: $seed_file" >&2
    failures+=("$seed_file")
  fi
  echo
done

if (( ${#failures[@]} > 0 )); then
  echo "Batch completed with ${#failures[@]} failure(s). Partial outputs are in:" >&2
  echo "  $output_dir" >&2
  for failed_seed in "${failures[@]}"; do
    echo "  - $failed_seed" >&2
  done
  exit 1
fi

echo "Batch generation complete."
echo "All generated TOMLs are in: $output_dir"
