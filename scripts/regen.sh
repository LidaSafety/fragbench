#!/usr/bin/env bash
# Regenerate fragments for a campaign and validate them in one command.
#
# Usage:
#     scripts/regen.sh <campaign> [num_variations] [base_seed]
#
# Examples:
#     scripts/regen.sh promptsteal              # 100 variations, base seed 0
#     scripts/regen.sh promptsteal 10           # 10 variations, base seed 0
#     scripts/regen.sh promptsteal 100 42       # 100 variations, base seed 42
#
# Reads seeds/<campaign>.json.
# Writes:
#     results/<campaign>_fragments.json
#     attacks/generated_<campaign>_<seed>.toml  (one per variation)
#     logs/coherence_<campaign>_<N>.json        (validator report)
#
# Exit code: 0 if validator passes, 1 if coherence errors found.

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <campaign> [num_variations] [base_seed]" >&2
    echo "Example: $0 promptsteal 100 0" >&2
    exit 2
fi

CAMPAIGN="$1"
NUM="${2:-100}"
SEED="${3:-0}"

SEED_FILE="seeds/${CAMPAIGN}.json"
OUT_JSON="results/${CAMPAIGN}_fragments.json"
LOG_JSON="logs/coherence_${CAMPAIGN}_${NUM}.json"

if [[ ! -f "$SEED_FILE" ]]; then
    echo "ERROR: seed file not found: $SEED_FILE" >&2
    exit 2
fi

echo "=== Generating ${NUM} variations of ${CAMPAIGN} (base seed ${SEED}) ==="
python3 run.py --generate \
    --seed-file "$SEED_FILE" \
    --num-variations "$NUM" \
    --seed "$SEED" \
    --stylize \
    --output-json "$OUT_JSON"

echo
echo "=== Validating ==="
python3 scripts/validate_fragments.py "$OUT_JSON" --log "$LOG_JSON"
