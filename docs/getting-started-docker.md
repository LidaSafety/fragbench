# FragBench — Getting Started (Docker)

Run attack TOML files through the MCP agent loop using Docker containers for full network isolation.

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| **Docker Desktop** | Install from [docker.com](https://www.docker.com/products/docker-desktop/). Must be running before you start. |
| **Ollama** | The target LLM runs on your host machine; Docker containers reach it via `host.docker.internal`. |
| **Make** | Pre-installed on macOS/Linux. Windows users can use WSL or install via `choco install make`. |

## Step 1 — Install and start Ollama

```bash
brew install ollama      # macOS — or see https://ollama.com/download
ollama serve
```

Leave that terminal open. Ollama is now listening on port 11434.

## Step 2 — Pull the target model

In a **new** terminal:

```bash
ollama pull huihui_ai/qwen3.5-abliterated:35b
```

This is ~20 GB on first pull. You can verify it downloaded with `ollama list`.

## Step 3 — Start the MCP servers + viewer

```bash
cd fragbench
docker compose up -d
```

This builds and starts all containers (MCP toolkit servers + frontend viewer). First run takes a few minutes to build images; subsequent runs are fast.

Verify everything is healthy:

```bash
docker compose ps
```

You should see ~25 containers in **Running** state.

## Step 4 — Run a single stage (quick smoke test)

```bash
make docker-attack-run \
  ATTACK_TOML=attacks/hello_world.toml \
  ATTACK_STAGE=0 \
  ATTACK_VARIATION_INDEX=0
```

This sends fragment 0, variation 0 through the MCP agent loop against the Ollama model. You'll see the prompt printed, the model's response, and any MCP tool calls it makes.

## Step 5 — Run the full kill chain

```bash
make docker-chain-run ATTACK_TOML=attacks/hello_world.toml
```

This runs every stage and every variation in the TOML sequentially, with a shared run ID. Each variation gets a randomized source IP and session ID for realistic logging.

## Step 6 — View results

Open **http://localhost:8787** in your browser. Click **Load Latest** or select the run ID from the dropdown to inspect the full conversation trace. You will have to keep refreshing it 

Session logs are also written to `logs/` as JSONL files.
Review these

## Step 7 — Tear down

```bash
docker compose down
```

Stop Ollama by pressing Ctrl-C in its terminal (or `killall ollama`).

---

## Other useful commands

### Interactive CLI

Drop into an interactive chat session with MCP tools available:

```bash
make docker-cli ATTACK_TOML=attacks/hello_world.toml
```

### Run a specific stage and variation

```bash
make docker-attack-run \
  ATTACK_TOML=attacks/hello_world.toml \
  ATTACK_STAGE=1 \
  ATTACK_VARIATION_INDEX=0
```

### Use a different model backend

```bash
# OpenRouter (requires OPENROUTER_API_KEY in env)
make docker-chain-run \
  ATTACK_TOML=attacks/hello_world.toml \
  MODEL_BACKEND=openrouter \
  MODEL=anthropic/claude-haiku-4.5
```

### List all available attack TOMLs

```bash
ls attacks/*.toml
```

### Check container status

```bash
make docker-status
```
