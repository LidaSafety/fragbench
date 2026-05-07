#!/usr/bin/env bash
set -euo pipefail
set -a; source .env; set +a

i=$1

# Auto-generated from rl_tables_base.tex: cells with no number (--- in base).
# 177 missing cells across 40 (dataset, judge, style) groups.
# Expected full grid: 3 datasets x 6 styles x 4 judges x 5 rewriters = 360.
# Run one copy at a time, or split this file into chunks if rate limits allow.

if [ $i = "0" ]; then
	bash ./run_grid.sh --datasets=dataset/dprk_fraud_llm.json --judges=anthropic/claude-sonnet-4-6 --styles=direct --rewriters=openai/gpt-5.4-mini-2026-03-17,azure/gpt-5.4,deepseek/deepseek-v4-flash
	bash ./run_grid.sh --datasets=dataset/dprk_fraud_llm.json --judges=anthropic/claude-sonnet-4-6 --styles=educational --rewriters=anthropic/claude-sonnet-4-6,anthropic/claude-opus-4-6,openai/gpt-5.4-mini-2026-03-17,azure/gpt-5.4,deepseek/deepseek-v4-flash
	bash ./run_grid.sh --datasets=dataset/dprk_fraud_llm.json --judges=anthropic/claude-opus-4-6 --styles=command_form --rewriters=anthropic/claude-opus-4-6
	bash ./run_grid.sh --datasets=dataset/dprk_fraud_llm.json --judges=anthropic/claude-opus-4-6 --styles=educational --rewriters=anthropic/claude-sonnet-4-6,anthropic/claude-opus-4-6,openai/gpt-5.4-mini-2026-03-17,azure/gpt-5.4,deepseek/deepseek-v4-flash
	bash ./run_grid.sh --datasets=dataset/dprk_fraud_llm.json --judges=anthropic/claude-opus-4-6 --styles=helpdesk --rewriters=anthropic/claude-sonnet-4-6,anthropic/claude-opus-4-6,openai/gpt-5.4-mini-2026-03-17,azure/gpt-5.4,deepseek/deepseek-v4-flash
	bash ./run_grid.sh --datasets=dataset/dprk_fraud_llm.json --judges=openai/gpt-5.4-mini --styles=command_form --rewriters=anthropic/claude-sonnet-4-6,anthropic/claude-opus-4-6,openai/gpt-5.4-mini-2026-03-17,azure/gpt-5.4,deepseek/deepseek-v4-flash
	bash ./run_grid.sh --datasets=dataset/dprk_fraud_llm.json --judges=openai/gpt-5.4-mini --styles=compliance_audit --rewriters=anthropic/claude-sonnet-4-6,anthropic/claude-opus-4-6,openai/gpt-5.4-mini-2026-03-17,azure/gpt-5.4,deepseek/deepseek-v4-flash
	bash ./run_grid.sh --datasets=dataset/dprk_fraud_llm.json --judges=openai/gpt-5.4-mini --styles=direct --rewriters=anthropic/claude-sonnet-4-6,anthropic/claude-opus-4-6,openai/gpt-5.4-mini-2026-03-17,azure/gpt-5.4,deepseek/deepseek-v4-flash
	bash ./run_grid.sh --datasets=dataset/dprk_fraud_llm.json --judges=openai/gpt-5.4-mini --styles=educational --rewriters=anthropic/claude-sonnet-4-6,anthropic/claude-opus-4-6,openai/gpt-5.4-mini-2026-03-17,azure/gpt-5.4,deepseek/deepseek-v4-flash
	bash ./run_grid.sh --datasets=dataset/dprk_fraud_llm.json --judges=openai/gpt-5.4-mini --styles=helpdesk --rewriters=anthropic/claude-sonnet-4-6,anthropic/claude-opus-4-6,openai/gpt-5.4-mini-2026-03-17,azure/gpt-5.4,deepseek/deepseek-v4-flash
elif [ $i = "1" ]; then
	bash ./run_grid.sh --datasets=dataset/dprk_fraud_llm.json --judges=openai/gpt-5.4-mini --styles=sysadmin --rewriters=anthropic/claude-sonnet-4-6,anthropic/claude-opus-4-6,openai/gpt-5.4-mini-2026-03-17,azure/gpt-5.4,deepseek/deepseek-v4-flash
	bash ./run_grid.sh --datasets=dataset/promptsteal_llm.json --judges=anthropic/claude-sonnet-4-6 --styles=compliance_audit --rewriters=azure/gpt-5.4,deepseek/deepseek-v4-flash
	bash ./run_grid.sh --datasets=dataset/promptsteal_llm.json --judges=anthropic/claude-sonnet-4-6 --styles=educational --rewriters=openai/gpt-5.4-mini-2026-03-17,deepseek/deepseek-v4-flash
	bash ./run_grid.sh --datasets=dataset/promptsteal_llm.json --judges=anthropic/claude-sonnet-4-6 --styles=helpdesk --rewriters=anthropic/claude-sonnet-4-6,anthropic/claude-opus-4-6,openai/gpt-5.4-mini-2026-03-17,azure/gpt-5.4,deepseek/deepseek-v4-flash
	bash ./run_grid.sh --datasets=dataset/promptsteal_llm.json --judges=anthropic/claude-sonnet-4-6 --styles=sysadmin --rewriters=anthropic/claude-sonnet-4-6,anthropic/claude-opus-4-6,openai/gpt-5.4-mini-2026-03-17,azure/gpt-5.4,deepseek/deepseek-v4-flash
	bash ./run_grid.sh --datasets=dataset/promptsteal_llm.json --judges=anthropic/claude-opus-4-6 --styles=command_form --rewriters=anthropic/claude-opus-4-6
	bash ./run_grid.sh --datasets=dataset/promptsteal_llm.json --judges=anthropic/claude-opus-4-6 --styles=compliance_audit --rewriters=anthropic/claude-sonnet-4-6,anthropic/claude-opus-4-6,openai/gpt-5.4-mini-2026-03-17,azure/gpt-5.4,deepseek/deepseek-v4-flash
	bash ./run_grid.sh --datasets=dataset/promptsteal_llm.json --judges=anthropic/claude-opus-4-6 --styles=direct --rewriters=anthropic/claude-sonnet-4-6,anthropic/claude-opus-4-6,openai/gpt-5.4-mini-2026-03-17,azure/gpt-5.4,deepseek/deepseek-v4-flash
	bash ./run_grid.sh --datasets=dataset/promptsteal_llm.json --judges=anthropic/claude-opus-4-6 --styles=helpdesk --rewriters=anthropic/claude-sonnet-4-6,anthropic/claude-opus-4-6,openai/gpt-5.4-mini-2026-03-17,azure/gpt-5.4,deepseek/deepseek-v4-flash
	bash ./run_grid.sh --datasets=dataset/promptsteal_llm.json --judges=anthropic/claude-opus-4-6 --styles=sysadmin --rewriters=anthropic/claude-sonnet-4-6,anthropic/claude-opus-4-6,openai/gpt-5.4-mini-2026-03-17,azure/gpt-5.4,deepseek/deepseek-v4-flash
elif [ $i = "2" ]; then
 	bash ./run_grid.sh --datasets=dataset/promptsteal_llm.json --judges=openai/gpt-5.4-mini --styles=command_form --rewriters=anthropic/claude-sonnet-4-6,anthropic/claude-opus-4-6,openai/gpt-5.4-mini-2026-03-17,azure/gpt-5.4,deepseek/deepseek-v4-flash
 	bash ./run_grid.sh --datasets=dataset/promptsteal_llm.json --judges=openai/gpt-5.4-mini --styles=compliance_audit --rewriters=anthropic/claude-sonnet-4-6,anthropic/claude-opus-4-6,openai/gpt-5.4-mini-2026-03-17,azure/gpt-5.4,deepseek/deepseek-v4-flash
 	bash ./run_grid.sh --datasets=dataset/promptsteal_llm.json --judges=openai/gpt-5.4-mini --styles=direct --rewriters=anthropic/claude-sonnet-4-6,anthropic/claude-opus-4-6,openai/gpt-5.4-mini-2026-03-17,azure/gpt-5.4,deepseek/deepseek-v4-flash
 	bash ./run_grid.sh --datasets=dataset/promptsteal_llm.json --judges=openai/gpt-5.4-mini --styles=educational --rewriters=anthropic/claude-sonnet-4-6,anthropic/claude-opus-4-6,openai/gpt-5.4-mini-2026-03-17,azure/gpt-5.4,deepseek/deepseek-v4-flash
 	bash ./run_grid.sh --datasets=dataset/promptsteal_llm.json --judges=openai/gpt-5.4-mini --styles=helpdesk --rewriters=anthropic/claude-sonnet-4-6,anthropic/claude-opus-4-6,openai/gpt-5.4-mini-2026-03-17,azure/gpt-5.4,deepseek/deepseek-v4-flash
 	bash ./run_grid.sh --datasets=dataset/promptsteal_llm.json --judges=openai/gpt-5.4-mini --styles=sysadmin --rewriters=anthropic/claude-sonnet-4-6,anthropic/claude-opus-4-6,openai/gpt-5.4-mini-2026-03-17,azure/gpt-5.4,deepseek/deepseek-v4-flash
 	bash ./run_grid.sh --datasets=dataset/quietvault_llm.json --judges=anthropic/claude-sonnet-4-6 --styles=compliance_audit --rewriters=anthropic/claude-opus-4-6,openai/gpt-5.4-mini-2026-03-17,azure/gpt-5.4,deepseek/deepseek-v4-flash
 	bash ./run_grid.sh --datasets=dataset/quietvault_llm.json --judges=anthropic/claude-sonnet-4-6 --styles=direct --rewriters=anthropic/claude-sonnet-4-6,anthropic/claude-opus-4-6,openai/gpt-5.4-mini-2026-03-17,azure/gpt-5.4,deepseek/deepseek-v4-flash
 	bash ./run_grid.sh --datasets=dataset/quietvault_llm.json --judges=anthropic/claude-sonnet-4-6 --styles=educational --rewriters=anthropic/claude-sonnet-4-6,anthropic/claude-opus-4-6,openai/gpt-5.4-mini-2026-03-17,azure/gpt-5.4,deepseek/deepseek-v4-flash
 	bash ./run_grid.sh --datasets=dataset/quietvault_llm.json --judges=anthropic/claude-sonnet-4-6 --styles=sysadmin --rewriters=anthropic/claude-sonnet-4-6,openai/gpt-5.4-mini-2026-03-17,azure/gpt-5.4,deepseek/deepseek-v4-flash
else
 	bash ./run_grid.sh --datasets=dataset/quietvault_llm.json --judges=anthropic/claude-opus-4-6 --styles=command_form --rewriters=anthropic/claude-opus-4-6
 	bash ./run_grid.sh --datasets=dataset/quietvault_llm.json --judges=anthropic/claude-opus-4-6 --styles=direct --rewriters=anthropic/claude-sonnet-4-6,openai/gpt-5.4-mini-2026-03-17,azure/gpt-5.4,deepseek/deepseek-v4-flash
 	bash ./run_grid.sh --datasets=dataset/quietvault_llm.json --judges=anthropic/claude-opus-4-6 --styles=educational --rewriters=anthropic/claude-sonnet-4-6,anthropic/claude-opus-4-6,openai/gpt-5.4-mini-2026-03-17,azure/gpt-5.4,deepseek/deepseek-v4-flash
 	bash ./run_grid.sh --datasets=dataset/quietvault_llm.json --judges=anthropic/claude-opus-4-6 --styles=helpdesk --rewriters=anthropic/claude-sonnet-4-6,anthropic/claude-opus-4-6,openai/gpt-5.4-mini-2026-03-17,azure/gpt-5.4,deepseek/deepseek-v4-flash
 	bash ./run_grid.sh --datasets=dataset/quietvault_llm.json --judges=openai/gpt-5.4-mini --styles=command_form --rewriters=anthropic/claude-sonnet-4-6,anthropic/claude-opus-4-6,openai/gpt-5.4-mini-2026-03-17,azure/gpt-5.4,deepseek/deepseek-v4-flash
 	bash ./run_grid.sh --datasets=dataset/quietvault_llm.json --judges=openai/gpt-5.4-mini --styles=compliance_audit --rewriters=anthropic/claude-sonnet-4-6,anthropic/claude-opus-4-6,openai/gpt-5.4-mini-2026-03-17,azure/gpt-5.4,deepseek/deepseek-v4-flash
 	bash ./run_grid.sh --datasets=dataset/quietvault_llm.json --judges=openai/gpt-5.4-mini --styles=direct --rewriters=anthropic/claude-sonnet-4-6,anthropic/claude-opus-4-6,openai/gpt-5.4-mini-2026-03-17,azure/gpt-5.4,deepseek/deepseek-v4-flash
 	bash ./run_grid.sh --datasets=dataset/quietvault_llm.json --judges=openai/gpt-5.4-mini --styles=educational --rewriters=anthropic/claude-sonnet-4-6,anthropic/claude-opus-4-6,openai/gpt-5.4-mini-2026-03-17,azure/gpt-5.4,deepseek/deepseek-v4-flash
 	bash ./run_grid.sh --datasets=dataset/quietvault_llm.json --judges=openai/gpt-5.4-mini --styles=helpdesk --rewriters=anthropic/claude-sonnet-4-6,anthropic/claude-opus-4-6,openai/gpt-5.4-mini-2026-03-17,azure/gpt-5.4,deepseek/deepseek-v4-flash
 	bash ./run_grid.sh --datasets=dataset/quietvault_llm.json --judges=openai/gpt-5.4-mini --styles=sysadmin --rewriters=anthropic/claude-sonnet-4-6,anthropic/claude-opus-4-6,openai/gpt-5.4-mini-2026-03-17,azure/gpt-5.4,deepseek/deepseek-v4-flash
fi
wait
