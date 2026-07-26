#!/bin/bash
#
# Full executed-benign grid: 24 campaigns x 6 styles x 9 seeds = 1,296 chains.
#
# Styles are the OUTER loop on purpose. The first pass covers all 24 campaigns
# at one style, so it doubles as the smoke test -- roughly three hours in you
# have seen every campaign execute, and the chains it produced are kept rather
# than thrown away. Check the summary after pass 1 before letting it run on.
#
# Seeds run concurrently within a campaign+style (MAX_PARALLEL_VARIATIONS), which
# is only safe because each variation embeds its own discriminator in every
# artifact name. Campaigns stay sequential: the harness restarts
# server-filesystem at the top of each invocation, so two concurrent campaigns
# would wipe each other's /workspace mid-run.
#
# JUDGE=0 -- the judge scores malicious objective completion, which is
# meaningless for benign work (it marked 45% of clean fragments FAIL in the smoke
# sweep) and costs one model call per fragment across 13,716 fragments. It scores
# a fragment after the fact and never alters the tool trace, which is the only
# thing the detector consumes.
#
# Resumable: each completed campaign+style drops a marker in run_state/. A failed
# invocation is deliberately left unmarked so it retries on the next pass.
#
# Usage:  ./run_benign_full.sh                  # the whole grid
#         STYLES=direct ./run_benign_full.sh    # pass 1 only (the smoke pass)
#         SEEDS=0-4 ./run_benign_full.sh        # cheaper grid
#         PAR=4 ./run_benign_full.sh            # throttle if rate-limited

set -uo pipefail            # NOT -e: one bad campaign must not stop the grid

STYLES="${STYLES:-direct command_form sysadmin compliance_audit educational helpdesk}"
SEEDS="${SEEDS:-0-8}"
PAR="${PAR:-9}"
FRAG_PAR="${FRAG_PAR:-2}"
JUDGE="${JUDGE:-0}"

STATE_DIR=run_state
LOG_DIR="run_logs/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$STATE_DIR" "$LOG_DIR"

CAMPAIGNS=(
    benign_sysadmin_capacity   benign_sysadmin_backup     benign_sysadmin_patching
    benign_sysadmin_certs      benign_sysadmin_storage    benign_it_onboarding
    benign_itsupport_asset     benign_itsupport_access    benign_itsupport_incident
    benign_compliance_access_review benign_compliance_vendor benign_compliance_retention
    benign_course_syllabus     benign_course_assessment   benign_course_lab
    benign_project_kickoff     benign_project_release     benign_project_retro
    benign_personal_inbox      benign_personal_relocation benign_data_survey
    benign_data_catalog        benign_docs_api            benign_docs_handbook
)

n_styles=$(set -- $STYLES; echo $#)
echo "grid: ${#CAMPAIGNS[@]} campaigns x $n_styles styles, seeds=$SEEDS, par=$PAR"
echo "logs -> $LOG_DIR   state -> $STATE_DIR"

for style in $STYLES; do
    echo
    echo "########## style: $style"
    for campaign in "${CAMPAIGNS[@]}"; do
        marker="$STATE_DIR/${campaign}__${style}.done"
        if [ -f "$marker" ]; then
            echo "  skip  $campaign ($style) -- already done"
            continue
        fi
        echo "=== $campaign [$style]"
        make docker-attack-graph-run \
            FRAGMENTS="results/${campaign}_manual.json" \
            STYLE="$style" \
            SEEDS="$SEEDS" \
            MCP_MODEL_BACKEND=openrouter \
            MCP_MODEL=qwen/qwen3.5-122b-a10b \
            JUDGE="$JUDGE" \
            MAX_PARALLEL_VARIATIONS="$PAR" \
            MAX_PARALLEL_FRAGMENTS="$FRAG_PAR" \
            2>&1 | tee "$LOG_DIR/${campaign}__${style}.log"
        status=${PIPESTATUS[0]}          # make's status, not tee's
        if [ $status -eq 0 ]; then
            touch "$marker"
        elif [ $status -eq 130 ]; then
            echo "  interrupted -- resume by re-running this script"
            exit 130
        else
            echo "  harness exited $status -- left unmarked, will retry"
        fi
    done
    echo
    echo "=== verdicts after style '$style' ==="
    python3 scripts/summarize_benign_run.py --since "$LOG_DIR" | tail -8
done
