#!/usr/bin/env bash
set -euo pipefail
set -a; source .env; set +a

# Auto-generated from rl_tables_base.tex by gen_rerun_flat.py.
# Includes cells that are --- (never run) AND cells with (0.0) / (+0.0) delta.
# Total cases: 266

bash ./run_grid.sh --datasets=dataset/dprk_fraud_llm.json --judges=anthropic/claude-opus-4-6 --styles=command_form --rewriters=anthropic/claude-opus-4-6
bash ./run_grid.sh --datasets=dataset/dprk_fraud_llm.json --judges=anthropic/claude-sonnet-4-6 --styles=direct --rewriters=deepseek/deepseek-v4-flash
bash ./run_grid.sh --datasets=dataset/dprk_fraud_llm.json --judges=anthropic/claude-sonnet-4-6 --styles=educational --rewriters=anthropic/claude-sonnet-4-6
bash ./run_grid.sh --datasets=dataset/dprk_fraud_llm.json --judges=anthropic/claude-sonnet-4-6 --styles=educational --rewriters=anthropic/claude-opus-4-6
bash ./run_grid.sh --datasets=dataset/dprk_fraud_llm.json --judges=anthropic/claude-sonnet-4-6 --styles=educational --rewriters=deepseek/deepseek-v4-flash
bash ./run_grid.sh --datasets=dataset/dprk_fraud_llm.json --judges=anthropic/claude-opus-4-6 --styles=educational --rewriters=anthropic/claude-sonnet-4-6
bash ./run_grid.sh --datasets=dataset/dprk_fraud_llm.json --judges=anthropic/claude-opus-4-6 --styles=educational --rewriters=anthropic/claude-opus-4-6
bash ./run_grid.sh --datasets=dataset/dprk_fraud_llm.json --judges=anthropic/claude-opus-4-6 --styles=educational --rewriters=deepseek/deepseek-v4-flash
bash ./run_grid.sh --datasets=dataset/dprk_fraud_llm.json --judges=anthropic/claude-opus-4-6 --styles=helpdesk --rewriters=anthropic/claude-sonnet-4-6
bash ./run_grid.sh --datasets=dataset/dprk_fraud_llm.json --judges=anthropic/claude-opus-4-6 --styles=helpdesk --rewriters=anthropic/claude-opus-4-6
bash ./run_grid.sh --datasets=dataset/dprk_fraud_llm.json --judges=anthropic/claude-opus-4-6 --styles=helpdesk --rewriters=deepseek/deepseek-v4-flash
bash ./run_grid.sh --datasets=dataset/dprk_fraud_llm.json --judges=anthropic/claude-sonnet-4-6 --styles=sysadmin --rewriters=anthropic/claude-opus-4-6
