#!/bin/sh

input=results/dprk_fraud_manual.json
echo "Running with $input"

for name in promptsteal; do
    make docker-attack-graph-run \
        FRAGMENTS=$input \
        STYLE=direct \
        SEEDS=0-3 \
        MCP_MODEL_BACKEND=openrouter \
        MCP_MODEL=qwen/qwen3.5-122b-a10b \
        JUDGE=1\
        JUDGE_MODEL=anthropic/claude-sonnet-4.6
done
