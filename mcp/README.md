# MCP CLI + Filesystem Server — Architecture & Session Walkthrough

This repo contains the minimal working implementation of an MCP (Model Context Protocol) agent loop
connected to a local filesystem server, along with recorded session logs and a notebook that
dissects how everything works together.

---

## What We Wanted to Track

### 1. The Agent Loop (`mcp_client_v1.py`)
`MCPOpenRouterClientV1` — a 3,848-line unified client that:
- Connects to any MCP server over SSE, streamable-HTTP, or stdio
- Routes LLM calls through OpenRouter (supports every model on the platform)
- Runs an iterative tool-calling loop: call LLM → dispatch tools in parallel → feed results back → repeat
- Exposes a `HookManager` for attaching loggers, RL trackers, budget controllers, etc.
- Supports optional Jina embedding retrieval, semantic tool selection, and RL-based iteration budgeting

### 2. The Filesystem Server (`servers/filesystem_server.py`)
A FastMCP server exposing **14 file-system tools** over HTTP (SSE or streamable-HTTP) on `127.0.0.1:8001`:

| Tool | What it does |
|------|-------------|
| `read_file` | Read file contents with offset/limit, 10MB cap |
| `read_file_bytes` | Binary-safe read, returns hex + preview |
| `write_file` | Create/overwrite, auto-creates parent dirs |
| `append_file` | Append to existing file |
| `edit_file` | Find-and-replace with optional replace_all |
| `list_directory` | List dir entries, optional recursive (1000 cap) |
| `create_directory` | `os.makedirs` with parents |
| `delete_path` | `rm -rf` for dirs, `os.remove` for files |
| `copy_path` | `shutil.copytree` / `copy2` |
| `move_path` | `shutil.move` |
| `glob_files` | Recursive glob, 500-match cap |
| `search_in_files` | Regex search with line numbers, 100-result cap |
| `file_info` | Size, timestamps, permissions, MIME type, uid/gid |
| `change_permissions` | `os.chmod` from octal string e.g. `'755'` |

Errors are always returned as structured JSON (`{"success": false, "error": "..."}`) so the LLM
can read them and self-correct in the next iteration without crashing.

### 3. The CLI Entry Point (`mcp_cli.py`)
Thin wrapper (~300 lines) that:
- Instantiates `MCPOpenRouterClientV1` in `mcp_only=True` mode (no Jina, no RL, no tool retrieval)
- Connects to `http://127.0.0.1:8001/mcp` over SSE
- Attaches a `ConversationLogger` that writes structured JSONL to `--log-dir`
- Provides a REPL (`>>>`) and a `--prompt` one-shot mode
- Supports `--model`, `--max-iterations`, `--temperature` overrides

### 4. The Conversation API (`conversation_aware_mcp_api.py`)
FastAPI service that wraps a `DynamicMCPToolkitManager` — dynamically selects which tools to
expose per conversation based on context, usage history, and semantic relevance. Runs on the
same `:8001` port as the filesystem server in alternate configurations.

### 5. Session Logs (`data-logs/`)
Four JSONL session logs captured during live testing. Each record has:
- `seq`, `ts`, `event` — sequence number, timestamp, event type
- Event-specific fields (see notebook cell 5 for full schema)

Key sessions:
- `session_20260313_115110.jsonl` — **22 tool calls in 12.4s** — model was asked to test all 14 tools, created `report-two.html`
- `session_20260313_115711.jsonl` — **30 tool calls in 15.4s** — model tested only tools starting with 'C', 5× each, then cleaned up
- `session_20260313_132317.jsonl` — short exit session
- `session_20260313_142427.jsonl` — short exit session

The `viewer.html` is a self-contained drag-drop viewer for any session JSONL — dark theme,
tool call timeline, success/fail rates, latency breakdown.

### 6. The Notebook (`mcp_cli_walkthrough.ipynb`)
16-cell Jupyter notebook covering:
1. Full architecture diagram (CLI → SSE → filesystem server)
2. Server bootstrap (FastMCP + Starlette routing)
3. Tool catalog with signatures and notes
4. `mcp_cli.py` wiring annotated
5. `process_query` agent loop pseudocode
6. Live parsing of all session logs
7. Tool call timeline trace for session 1
8. JSONL event schema reference
9. Aggregate stats across all sessions (tool frequency, success rate, wall time)
10. How to run it

---

## FragBench Pipeline: Seed → Variation → MCP

FragBench attacks are defined as **seeds** (JSON prompt templates) and executed via **variation classes** that resolve the templates deterministically. The MCP client is the execution layer that runs the resulting prompts against a live agent with tools.

```
seeds/hello_world.json          ← prompt template + variable pools
        │
        ▼
HelloWorldVariation(seed=42)    ← resolves variables with seeded RNG → prompt string
        │
        ▼
MCPOpenRouterClientV1           ← LLM agent loop with filesystem tools
        │
        ▼
agent executes the task (e.g. lists Python files via glob_files)
```

### Quick start

```python
from variations.hello_world import HelloWorldVariation

gen = HelloWorldVariation("seeds/hello_world.json")
prompt, tactic = gen.make_variation(seed=42)[0]
# → "List all Python files in the ./mcp directory."
```

Then send that prompt through the MCP client (see `fragbench_demo.ipynb` for the full async wiring).

### Adding a new attack

1. Copy `seeds/_template.json` → `seeds/<your_attack>.json` and fill in the stages.
2. Create `variations/<your_attack>.py` inheriting from `BaseVariation` (see `variations/hello_world.py` for the minimal pattern, `variations/vibe_extortion.py` for a full example).
3. Call `gen.make_variation(seed)` to generate a prompt and pass it to `client.process_query()`.

### Interactive demo notebook

```bash
uv run jupyter lab mcp/fragbench_demo.ipynb
```

---

## How to Run

### One-command stack startup (Makefile)

From repo root:

```bash
make stack-ready
```

This starts all configured MCP toolkit servers (`filesystem`, `shell`, `archive`, `exfil`, `network`).

Run maple-oriented preflight checks (backend/env + endpoint reachability):

```bash
make maple-check MODEL_BACKEND=openrouter
```

Or start + verify in one command:

```bash
make maple-ready MODEL_BACKEND=openrouter
```

Run interactive CLI with attack-aware toolkit routing:

```bash
make cli ATTACK_SEED=seeds/hello_world.json MODEL_BACKEND=openrouter
```

When using Ollama backend, set an Ollama model name (not OpenRouter model ids):

```bash
make cli MODEL_BACKEND=ollama MODEL=huihui_ai/qwen3.5-abliterated:35b
```

Run one-shot hello-world variation:

```bash
make hello-run ATTACK_SEED=seeds/hello_world.json MODEL_BACKEND=openrouter
```

Run one-shot attack stage generated from any registered variation:

```bash
make attack-run ATTACK_SEED=seeds/promptsteal.json ATTACK_VARIATION_SEED=42 ATTACK_STAGE=1 MODEL_BACKEND=openrouter
```

Stop everything:

```bash
make stack-down
```

The `ATTACK_SEED` argument is passed to `mcp_cli.py --attack-seed`, which triggers
`AttackProfileBuilder` to derive tactics/tags from the seed and lets `ToolkitRouter`
choose the relevant toolkits from `mcp/registry/toolkits.toml`.

### Backend portability (OpenRouter + Ollama + vLLM)

The CLI now supports backend routing:

```bash
# OpenRouter (default)
uv run mcp/mcp_cli.py --model-backend openrouter --model anthropic/claude-haiku-4.5

# Ollama local
uv run mcp/mcp_cli.py --model-backend ollama --model huihui_ai/qwen3.5-abliterated:35b

# vLLM OpenAI-compatible local
uv run mcp/mcp_cli.py --model-backend vllm --vllm-base-url http://127.0.0.1:8000/v1 --model huihui-ai/Huihui-Qwen3.5-35B-A3B-abliterated
```

### Registry-driven toolkit loading

Use `mcp/registry/toolkits.toml` to define toolkits and connect the selected set:

```bash
uv run mcp/mcp_cli.py \
  --auto-toolkits \
  --registry-path mcp/registry/toolkits.toml \
  --attack-seed seeds/promptsteal.json \
  --execution-mode simulated
```

### New simulation toolkit servers

- `mcp/servers/shell_server.py`
- `mcp/servers/archive_server.py`
- `mcp/servers/exfil_server.py`
- `mcp/servers/network_recon_server.py`

Each server is simulation-first and supports bounded-real operation only when explicitly enabled.

### Deployment on maple

Maple setup docs and bootstrap scripts:

- `mcp/deploy/bootstrap_mcp_env.sh`
- `mcp/deploy/maple_abliterated_setup.md`
- `scripts/maple_tmux.sh` (tmux-based maple launcher)

Start maple tmux workspace:

```bash
bash scripts/maple_tmux.sh openrouter
# or
bash scripts/maple_tmux.sh ollama
# or
bash scripts/maple_tmux.sh vllm
```

**Start the filesystem server:**
```bash
uv run mcp/servers/filesystem_server.py --transport sse --port 8001
```

**Start the CLI (REPL):**
```bash
export OPENROUTER_API_KEY=
uv run mcp/mcp_cli.py --log-dir ./data-logs
```

**One-shot:**
```bash
uv run mcp_cli.py --prompt "list all python files" --log-dir ./data-logs
```

**Override model:**
```bash
uv run mcp_cli.py --model google/gemini-2.5-pro-preview --log-dir ./data-logs
```

**Open the notebook:**
```bash
uv run jupyter lab mcp_cli_walkthrough.ipynb
```

**View session logs:**
```
open data-logs/viewer.html
```

**View logs with self-contained v2 viewer:**
```
open data-logs/viewer-v2.html
```

---

## Architecture

```
┌──────────────────┐  SSE over HTTP  ┌──────────────────────────────────┐
│   mcp_cli.py     │ ◄────────────► │ servers/filesystem_server.py      │
│   (terminal)     │  :8001/mcp     │ FastMCP("filesystem") + Starlette  │
└───────┬──────────┘                └──────────────────────────────────┘
        │ delegates to                  14 tools, all return structured JSON
        ▼
┌───────────────────────┐
│ MCPOpenRouterClientV1 │   OpenRouter API (any model)
│ ─ agent loop          │ ◄────────────────────────────
│ ─ parallel tool calls │
│ ─ JSONL hook logger   │
└───────────────────────┘
        │ writes
        ▼
data-logs/session_*.jsonl  →  viewer.html
```
