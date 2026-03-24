# Maple Deployment Playbook (Abliterated Model + MCP)

This document sets up a dual-runtime local model path on maple and links it to the MCP toolkit layer.

Reference model: [huihui-ai/Huihui-Qwen3.5-35B-A3B-abliterated](https://huggingface.co/huihui-ai/Huihui-Qwen3.5-35B-A3B-abliterated)

## 1) Runtime layout

- `ollama` for quick local inference and easy operator experience.
- `vLLM` for OpenAI-compatible API serving and throughput-oriented runs.
- MCP client switches backend via `--model-backend` in `mcp/mcp_cli.py`.

## 2) Environment bootstrap

```bash
cd /path/to/fragbench/mcp/deploy
chmod +x bootstrap_mcp_env.sh
./bootstrap_mcp_env.sh /opt/fragbench-mcp
source /opt/fragbench-mcp/.venv/bin/activate
```

## 3) Ollama path

Prerequisite: install Ollama >= 0.17.5 on maple.

```bash
ollama pull huihui_ai/qwen3.5-abliterated:35b
ollama run huihui_ai/qwen3.5-abliterated:35b
```

MCP client example:

```bash
python mcp/mcp_cli.py \
  --model-backend ollama \
  --model huihui_ai/qwen3.5-abliterated:35b \
  --auto-toolkits \
  --attack-seed seeds/promptsteal.json
```

## 4) vLLM path (OpenAI-compatible)

Install vLLM in a dedicated env if needed.

```bash
python -m pip install vllm
python -m vllm.entrypoints.openai.api_server \
  --model huihui-ai/Huihui-Qwen3.5-35B-A3B-abliterated \
  --host 0.0.0.0 \
  --port 8000 \
  --dtype bfloat16 \
  --gpu-memory-utilization 0.90 \
  --max-model-len 8192
```

MCP client example:

```bash
python mcp/mcp_cli.py \
  --model-backend vllm \
  --vllm-base-url http://127.0.0.1:8000/v1 \
  --model huihui-ai/Huihui-Qwen3.5-35B-A3B-abliterated \
  --auto-toolkits \
  --attack-seed seeds/vibe_extortion.json
```

## 5) Safety isolation for bounded-real mode

Use bounded-real mode only with explicit controls:

- Dedicated service user.
- Containerized MCP servers with restricted mounts.
- Outbound allowlist for exfil simulation endpoints.
- `--execution-mode bounded_real` and `--execution-root <allowed_dir>`.

## 6) GPU sizing guidance

- 35B BF16 class models typically require multi-GPU configurations for strong throughput.
- Prefer quantized variants for single-GPU experiments.
- Keep separate cache volumes for Hugging Face and Ollama model stores.

