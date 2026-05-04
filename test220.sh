#!/bin/bash

STYLES="command_form compliance_audit direct educational helpdesk sysadmin"

INPUTS=<<EOF
results/ad_discovery_llm.json
results/ai-phishing_llm.json
results/clickfix_llm.json
results/coinbait_llm.json
results/coral_sleet_llm.json
results/deepfake-id-fraud_llm.json
results/dprk_fraud_llm.json
results/gtg1002_llm.json
results/honestcue_llm.json
results/jasper_sleet_llm.json
results/london_drugs_lockbit_llm.json
results/malterminal_llm.json
results/nocode_ransomware_llm.json
results/ns_power_ransomware_llm.json
results/operation_dream_job_llm.json
results/operation_false_witness_llm.json
results/promptflux_llm.json
results/promptsteal_llm.json
results/quietvault_llm.json
results/ru_malware_clusters_llm.json
results/scope_creep_llm.json
results/tycoon2fa_llm.json
results/vibe_extortion_llm.json
results/wormgpt_kawaiigpt_llm.json
EOF

time for input in $INPUTS; do
    for style in $STYLES; do
        echo "=== $input $style"
        make docker-attack-graph-run \
            FRAGMENTS=$input \
            STYLE=$style \
            SEEDS=0-9 \
            MCP_MODEL_BACKEND=openrouter \
            MCP_MODEL=qwen/qwen3.5-122b-a10b \
            JUDGE=1\
            JUDGE_MODEL=anthropic/claude-sonnet-4.6
    done
done
