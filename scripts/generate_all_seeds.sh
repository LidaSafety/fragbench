#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/.." && pwd)"
cd "$repo_root"

usage() {
  cat <<'EOF'
Batch-generate attack TOMLs for every seed JSON.

Usage:
  scripts/generate_all_seeds.sh [options]

Options:
  -n, --num-variations <int>  Variations per seed (default: 100)
  -s, --seeds-dir <path>       Seed directory (default: seeds)
  -o, --output-base-dir <path> Parent dir for fresh batch output dir
                              (default: attacks/batches)
  -h, --help                   Show this help

Behavior:
  - Creates a fresh output directory for each run.
  - Runs plain generation only (no --fragment / --legitimize).
  - Writes all generated TOMLs into that directory via --attacks-dir.
  - Continues across seed files and exits non-zero if any seed fails.
EOF
}

num_variations=500
seeds_dir="seeds"
output_base_dir="attacks/batches"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--num-variations)
      if [[ $# -lt 2 ]]; then
        echo "ERROR: $1 requires a value" >&2
        exit 1
      fi
      num_variations="$2"
      shift 2
      ;;
    -s|--seeds-dir)
      if [[ $# -lt 2 ]]; then
        echo "ERROR: $1 requires a value" >&2
        exit 1
      fi
      seeds_dir="$2"
      shift 2
      ;;
    -o|--output-base-dir)
      if [[ $# -lt 2 ]]; then
        echo "ERROR: $1 requires a value" >&2
        exit 1
      fi
      output_base_dir="$2"
      shift 2
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
echo

failures=()

for seed_file in "${seed_files[@]}"; do
  echo "==> Generating from $seed_file"
  if uv run run.py --generate --seed-file "$seed_file" --num-variations "$num_variations" --attacks-dir "$output_dir"; then
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
