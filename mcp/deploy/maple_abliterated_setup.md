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

## 5) Docker-isolated bounded-real mode (recommended)

The `docker-compose.yml` at the repo root runs all MCP servers, the attack
client, and the viewer in separate containers on restricted Docker networks.
**No model runtime is included** — Ollama, vLLM, or OpenRouter must be
available separately (see "Choosing a backend" below).

### 5.1) Prerequisites

- Docker Engine >= 24 (or Docker Desktop with compose v2).
- A model backend: either an `OPENROUTER_API_KEY`, or Ollama / vLLM already
  running on the host *outside* Docker.

### 5.2) One-command start (servers + viewer)

```bash
docker compose build          # first time only
docker compose up -d          # starts 5 MCP servers + frontend viewer
```

This does **not** start the client or any model. The servers sit idle until a
client connects. Verify with:

```bash
docker compose ps             # all 6 services should be "running"
open http://localhost:8787    # viewer (empty until first attack run)
```

### 5.3) Launching attacks

Every attack is a `docker compose run` of the `mcp-client` service.
Flags after `mcp-client` are passed straight through to `mcp_cli.py`.

**Minimal (simulated, OpenRouter):**

```bash
OPENROUTER_API_KEY=sk-... \
docker compose run --rm mcp-client \
  --auto-toolkits \
  --attack-seed seeds/promptsteal.json
```

**Bounded-real with workspace isolation:**

```bash
OPENROUTER_API_KEY=sk-... \
docker compose run --rm mcp-client \
  --auto-toolkits \
  --execution-mode bounded_real \
  --execution-root /workspace \
  --attack-seed seeds/promptsteal.json
```

**With a specific attack seed and interactive mode:**

```bash
OPENROUTER_API_KEY=sk-... \
docker compose run --rm mcp-client \
  --auto-toolkits \
  --attack-seed seeds/vibe_extortion.json
```

Once the client exits, reload the viewer at `http://localhost:8787` and click
**Load Latest** to see the session.

### 5.4) Choosing a backend (OpenRouter vs Ollama vs vLLM)

The Docker setup **does not bundle a model**. You choose the backend per run.

#### OpenRouter (default — no local GPU needed)

```bash
OPENROUTER_API_KEY=sk-... \
docker compose run --rm mcp-client \
  --model anthropic/claude-haiku-4.5 \
  --auto-toolkits \
  --attack-seed seeds/promptsteal.json
```

#### Ollama (running on the host)

Start Ollama on the host first (`ollama serve`), then:

```bash
# macOS / Windows (host.docker.internal resolves to host)
docker compose run --rm mcp-client \
  --model-backend ollama \
  --model huihui_ai/qwen3.5-abliterated:35b \
  --auto-toolkits \
  --attack-seed seeds/promptsteal.json

# Linux (use host network so container can reach localhost:11434)
docker compose run --rm --network host mcp-client \
  --model-backend ollama \
  --model huihui_ai/qwen3.5-abliterated:35b \
  --auto-toolkits \
  --attack-seed seeds/promptsteal.json
```

You can also set `OLLAMA_BASE_URL` to point at a remote Ollama instance:

```bash
OLLAMA_BASE_URL=http://192.168.1.50:11434 \
docker compose run --rm mcp-client \
  --model-backend ollama --model llama3:8b \
  --auto-toolkits --attack-seed seeds/promptsteal.json
```

#### vLLM (running on the host)

```bash
VLLM_BASE_URL=http://host.docker.internal:8000/v1 \
docker compose run --rm mcp-client \
  --model-backend vllm \
  --model huihui-ai/Huihui-Qwen3.5-35B-A3B-abliterated \
  --auto-toolkits \
  --attack-seed seeds/promptsteal.json
```

### 5.5) Setting the variation seed for an attack

Each attack seed JSON (e.g. `seeds/promptsteal.json`) defines
`variation_dimensions` that control prompt phrasing, collection scope, exfil
method, etc. The corresponding **attack TOML** (e.g.
`attacks/promptsteal.toml`) contains the expanded fragment variations with
named styles like `direct`, `sysadmin`, `developer`, `educational`.

To select a specific attack + variation set, pass the matching seed:

```bash
# promptsteal (APT28 LAMEHUG kill-chain)
docker compose run --rm mcp-client \
  --auto-toolkits --attack-seed seeds/promptsteal.json

# vibe_extortion (different campaign)
docker compose run --rm mcp-client \
  --auto-toolkits --attack-seed seeds/vibe_extortion.json
```

The `--attack-seed` flag drives:
1. **Toolkit selection** — the seed's MITRE tactics determine which MCP
   servers the client connects to (filesystem, shell, archive, exfil, network).
2. **Fragment ordering** — the viewer maps each turn to the seed's
   `attack_stages` for MITRE attribution and variation display.

Available seeds:

| Seed file | Campaign | Technique |
|-----------|----------|-----------|
| `seeds/promptsteal.json` | APT28 LAMEHUG | T1048 Exfil over Alt Protocol |
| `seeds/vibe_extortion.json` | Vibe Extortion | varies |
| `seeds/honestcue.json` | HonestCue | varies |
| `seeds/hello_world.json` | Hello World (test) | minimal |

### 5.6) Useful client flags

| Flag | Purpose |
|------|---------|
| `--model <name>` | Override model (default: `anthropic/claude-haiku-4.5`) |
| `--model-backend <openrouter\|ollama\|vllm>` | Select LLM backend |
| `--execution-mode <simulated\|bounded_real>` | Simulated (stub) vs real I/O |
| `--execution-root /workspace` | Sandbox root for bounded_real |
| `--max-iterations <n>` | Max agentic loop iterations (default: 6) |
| `--temperature <f>` | Sampling temperature (default: 0.6) |
| `--prompt "<text>"` | One-shot prompt, then exit |
| `--run-id <id>` | Tag session logs with a run ID |
| `--campaign <name>` | Tag session logs with a campaign name |
| `--attack-seed <path>` | Seed JSON for toolkit routing |
| `--allow-egress-host <host>` | Allowlist a hostname for bounded exfil (repeatable) |

### 5.7) Network topology

| Network | Access | Services |
|---------|--------|----------|
| `mcp-internal` | No internet (`internal: true`) | All MCP servers + client |
| `egress-limited` | Outbound only | `exfil-server` + `mcp-client` |
| `viewer-net` | Host-exposed | `viewer` on port 8787 |

### 5.8) Isolation controls

- **Read-only rootfs** on all server containers (except archive which needs write for tar).
- **Unprivileged user** (`fragbench`) inside every container.
- **`no-new-privileges`** security option on all services.
- **Resource limits** (512 MB / 1 CPU per server; 1 GB / 2 CPU for client).
- **Volume-scoped filesystem** — the workspace is a Docker volume, not a host mount.
- **Internal-only network** — servers cannot reach the internet.
- **Docker DNS** — `toolkits.docker.toml` resolves toolkits by service name.

### 5.9) Host mount variant

To expose a specific host directory as the attack workspace:

```bash
docker compose run --rm \
  -v /path/on/host:/workspace \
  mcp-client \
  --execution-mode bounded_real \
  --execution-root /workspace \
  --auto-toolkits \
  --attack-seed seeds/promptsteal.json
```

### 5.10) Tear down

```bash
docker compose down       # stop containers, keep volumes (session logs)
docker compose down -v    # stop containers and delete volumes
```

## 6) GPU sizing guidance

- 35B BF16 class models typically require multi-GPU configurations for strong throughput.
- Prefer quantized variants for single-GPU experiments.
- Keep separate cache volumes for Hugging Face and Ollama model stores.

