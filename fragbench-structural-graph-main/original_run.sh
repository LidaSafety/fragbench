set -a; source .env; set +a
# Llama Guard judge
bash ./run_grid.sh --judges=meta-llama/llama-guard-4-12b   --datasets=dataset/dprk_fraud_llm.json
bash ./run_grid.sh --judges=meta-llama/llama-guard-4-12b   --datasets=dataset/promptsteal_llm.json
bash ./run_grid.sh --judges=meta-llama/llama-guard-4-12b   --datasets=dataset/quietvault_llm.json

# Sonnet judge
bash ./run_grid.sh --judges=anthropic/claude-sonnet-4-6    --datasets=dataset/dprk_fraud_llm.json
bash ./run_grid.sh --judges=anthropic/claude-sonnet-4-6    --datasets=dataset/promptsteal_llm.json
bash ./run_grid.sh --judges=anthropic/claude-sonnet-4-6    --datasets=dataset/quietvault_llm.json

# Opus judge - NOT
bash ./run_grid.sh --judges=anthropic/claude-opus-4-6      --datasets=dataset/dprk_fraud_llm.json
bash ./run_grid.sh --judges=anthropic/claude-opus-4-6      --datasets=dataset/promptsteal_llm.json
bash ./run_grid.sh --judges=anthropic/claude-opus-4-6      --datasets=dataset/quietvault_llm.json

# GPT-mini judge
bash ./run_grid.sh --judges=openai/gpt-5.4-mini --datasets=dataset/dprk_fraud_llm.json
bash ./run_grid.sh --judges=openai/gpt-5.4-mini --datasets=dataset/promptsteal_llm.json
bash ./run_grid.sh --judges=openai/gpt-5.4-mini --datasets=dataset/quietvault_llm.json