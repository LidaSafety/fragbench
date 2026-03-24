#!/usr/bin/env bash
set -euo pipefail

# Maple tmux launcher for FragBench MCP stack.
#
# Usage:
#   scripts/maple_tmux.sh [openrouter|ollama|vllm]
#
# Optional env overrides:
#   SESSION_NAME=fragbench-maple
#   REPO_DIR=/path/to/fragbench
#   VENV_ACTIVATE=/opt/fragbench-mcp/.venv/bin/activate
#   MODEL=anthropic/claude-haiku-4.5
#   ATTACK_SEED=seeds/hello_world.json
#   ATTACK_VARIATION_SEED=42
#   ATTACK_STAGE=0
#   OLLAMA_BASE_URL=http://127.0.0.1:11434
#   VLLM_BASE_URL=http://127.0.0.1:8000/v1
#   VLLM_API_KEY=EMPTY

BACKEND="${1:-openrouter}"
SESSION_NAME="${SESSION_NAME:-fragbench-maple}"
REPO_DIR="${REPO_DIR:-$(pwd)}"
VENV_ACTIVATE="${VENV_ACTIVATE:-/opt/fragbench-mcp/.venv/bin/activate}"

if [[ -z "${MODEL:-}" ]]; then
  case "$BACKEND" in
    openrouter) MODEL="anthropic/claude-haiku-4.5" ;;
    ollama) MODEL="huihui_ai/qwen3.5-abliterated:35b" ;;
    vllm) MODEL="huihui-ai/Huihui-Qwen3.5-35B-A3B-abliterated" ;;
  esac
fi
ATTACK_SEED="${ATTACK_SEED:-seeds/hello_world.json}"
ATTACK_VARIATION_SEED="${ATTACK_VARIATION_SEED:-42}"
ATTACK_STAGE="${ATTACK_STAGE:-0}"
OLLAMA_BASE_URL="${OLLAMA_BASE_URL:-http://127.0.0.1:11434}"
VLLM_BASE_URL="${VLLM_BASE_URL:-http://127.0.0.1:8000/v1}"
VLLM_API_KEY="${VLLM_API_KEY:-EMPTY}"

if ! command -v tmux >/dev/null 2>&1; then
  echo "ERROR: tmux is not installed."
  exit 1
fi

if [[ ! -d "$REPO_DIR" ]]; then
  echo "ERROR: REPO_DIR does not exist: $REPO_DIR"
  exit 1
fi

if [[ "$BACKEND" != "openrouter" && "$BACKEND" != "ollama" && "$BACKEND" != "vllm" ]]; then
  echo "ERROR: backend must be one of: openrouter, ollama, vllm"
  exit 1
fi

if [[ "$BACKEND" == "openrouter" && -z "${OPENROUTER_API_KEY:-}" ]]; then
  echo "ERROR: OPENROUTER_API_KEY is required for openrouter backend."
  exit 1
fi

if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
  echo "Session already exists: $SESSION_NAME"
  echo "Attach with: tmux attach -t $SESSION_NAME"
  exit 0
fi

BASE_INIT="cd \"$REPO_DIR\""
if [[ -f "$VENV_ACTIVATE" ]]; then
  BASE_INIT="$BASE_INIT && source \"$VENV_ACTIVATE\""
fi

tmux new-session -d -s "$SESSION_NAME" -c "$REPO_DIR"
tmux split-window -h -t "${SESSION_NAME}:0"
tmux split-window -v -t "${SESSION_NAME}:0.0"
tmux split-window -v -t "${SESSION_NAME}:0.1"
tmux select-layout -t "${SESSION_NAME}:0" tiled

# Pane 0: model backend
if [[ "$BACKEND" == "openrouter" ]]; then
  MODEL_CMD="$BASE_INIT && echo \"Using OpenRouter backend (OPENROUTER_API_KEY loaded)\""
elif [[ "$BACKEND" == "ollama" ]]; then
  MODEL_CMD="$BASE_INIT && ollama serve"
else
  MODEL_CMD="$BASE_INIT && python -m vllm.entrypoints.openai.api_server --model huihui-ai/Huihui-Qwen3.5-35B-A3B-abliterated --host 0.0.0.0 --port 8000 --dtype bfloat16 --gpu-memory-utilization 0.90 --max-model-len 8192"
fi
tmux send-keys -t "${SESSION_NAME}:0.0" "$MODEL_CMD" C-m

# Pane 1: stack and checks
STACK_CMD="$BASE_INIT && make maple-ready MODEL_BACKEND=$BACKEND MODEL=$MODEL OLLAMA_BASE_URL=$OLLAMA_BASE_URL VLLM_BASE_URL=$VLLM_BASE_URL VLLM_API_KEY=$VLLM_API_KEY ATTACK_SEED=$ATTACK_SEED"
tmux send-keys -t "${SESSION_NAME}:0.1" "$STACK_CMD" C-m

# Pane 2: run attacks
RUN_CMD="$BASE_INIT && echo \"Ready to run attacks.\" && echo \"Example:\" && echo \"make attack-run MODEL_BACKEND=$BACKEND MODEL=$MODEL ATTACK_SEED=$ATTACK_SEED ATTACK_VARIATION_SEED=$ATTACK_VARIATION_SEED ATTACK_STAGE=$ATTACK_STAGE\""
tmux send-keys -t "${SESSION_NAME}:0.2" "$RUN_CMD" C-m

# Pane 3: status and logs
LOG_CMD="$BASE_INIT && watch -n 2 'make stack-status'"
tmux send-keys -t "${SESSION_NAME}:0.3" "$LOG_CMD" C-m

echo "Session created: $SESSION_NAME"
echo "Attach with: tmux attach -t $SESSION_NAME"
