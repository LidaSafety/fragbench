#!/bin/bash
#
# Smoke-test every executed-benign campaign: one chain each, before committing
# to the full 504-chain run. A campaign whose fragment N fails repeatably would
# otherwise waste 21 chains' worth of execution.
#
# STYLE=direct and SEEDS=0 means one chain per campaign (4 to 16 fragments).
# JUDGE=0 because the judge scores malicious objective completion and is
# meaningless here -- only the tool traces are consumed downstream.
#
# Usage:  ./smoke_benign.sh              # all 24 campaigns
#         ./smoke_benign.sh results/benign_docs_api_manual.json   # just one

set -uo pipefail            # NOT -e: one bad campaign must not stop the sweep

LOG_DIR="smoke_logs/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$LOG_DIR"

if [ $# -gt 0 ]; then
    INPUTS=("$@")
else
    INPUTS=(
        results/benign_sysadmin_capacity_manual.json
        results/benign_sysadmin_backup_manual.json
        results/benign_sysadmin_patching_manual.json
        results/benign_sysadmin_certs_manual.json
        results/benign_sysadmin_storage_manual.json
        results/benign_it_onboarding_manual.json
        results/benign_itsupport_asset_manual.json
        results/benign_itsupport_access_manual.json
        results/benign_itsupport_incident_manual.json
        results/benign_compliance_access_review_manual.json
        results/benign_compliance_vendor_manual.json
        results/benign_compliance_retention_manual.json
        results/benign_course_syllabus_manual.json
        results/benign_course_assessment_manual.json
        results/benign_course_lab_manual.json
        results/benign_project_kickoff_manual.json
        results/benign_project_release_manual.json
        results/benign_project_retro_manual.json
        results/benign_personal_inbox_manual.json
        results/benign_personal_relocation_manual.json
        results/benign_data_survey_manual.json
        results/benign_data_catalog_manual.json
        results/benign_docs_api_manual.json
        results/benign_docs_handbook_manual.json
    )
fi

echo "smoke-testing ${#INPUTS[@]} campaigns -> $LOG_DIR"

time for input in "${INPUTS[@]}"; do
    name=$(basename "$input" _manual.json)
    echo "=== $input"
    make docker-attack-graph-run \
        FRAGMENTS="$input" \
        STYLE=direct \
        SEEDS=0 \
        MCP_MODEL_BACKEND=openrouter \
        MCP_MODEL=qwen/qwen3.5-122b-a10b \
        JUDGE=0 \
        MAX_PARALLEL_VARIATIONS=4 \
        MAX_PARALLEL_FRAGMENTS=2 \
        2>&1 | tee "$LOG_DIR/$name.log"
    status=${PIPESTATUS[0]}          # make's status, not tee's
    if [ $status -ne 0 ]; then
        echo "    harness exited $status -- see $LOG_DIR/$name.log"
    fi
done

echo
echo "=== per-campaign verdicts ==="
python3 scripts/summarize_benign_run.py --since "$LOG_DIR"
