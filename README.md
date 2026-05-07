# fragbench

FragBench is a benchmark pipeline for evaluating whether LLM agents can complete multi-step attack chains when prompts are fragmented, rewritten, and executed through tool access. The workflow has three stages: **generate** fragment datasets from campaign seeds, optionally **rewrite** them with the RL/judge loop in `fragbench-structural-graph-main`, then **validate** execution through the Dockerized MCP agent harness.

---

## Prerequisites (by stage)

| Stage | Requirements |
|--------|----------------|
| **1. Dataset generation** | Python ≥ 3.11, [`uv`](https://docs.astral.sh/uv/getting-started/installation/). For LLM stylization: `ANTHROPIC_API_KEY`. |
| **2. Reinforcement Learning based Rewriting** | Same Python env; `ANTHROPIC_API_KEY` and/or `OPENROUTER_API_KEY` as required by the selected backends (see §2). |
| **3. MCP validation** | Docker Desktop, Make, **`OPENROUTER_API_KEY`** for the default target (`openrouter`). Optional: **Ollama** on the host when using `MCP_MODEL_BACKEND=ollama`. Judge keys are required when `JUDGE=1` and the selected judge backend requires them. |

Install Python dependencies from the repo root:

```bash
uv venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
uv pip install -e .
```

---

## 1. Dataset generation

FragBench builds its datasets from **public cyber-incident reporting**, which is distilled into **attack campaigns**. Each campaign lives as one JSON seed under `seeds/`; it describes the ordered steps an adversary would execute. Note that `seeds/` contains real campaign templates derived from public threat intel (GTIG, Anthropic TI, OpenAI disruption reports, Microsoft AI tradecraft report).

**Dataset generation** expands that seed into a **fragmented** benchmark: the story is broken into discrete steps, each wrapped in **benign cover** so rewritten prompts still read like plausible user or operator sessions rather than bare attack text. The pipeline emits the fragments JSON (`variations`, per-fragment styles, and `produces` / `consumes` links) which are further rewritten using RL (optional) or validated using the MCP harness.

Two ways to **generate** those fragments:

### 1.1 Manual (deterministic, no API)

No model calls, no API key:

```bash
python run.py --generate --seed-file seeds/promptsteal.json --seed 0 \
  --output-json results/promptsteal_manual.json
```

### 1.2 LLM stylization (requires Anthropic API Key)

Rephrases style via the LLM (`--no-style-templates`):

```bash
export ANTHROPIC_API_KEY=sk-ant-...
python run.py --generate --seed-file seeds/promptsteal.json \
  --no-style-templates --max-concurrency 32 \
  --output-json results/promptsteal_llm.json
```


#### Available seeds
Swap `promptsteal` for any seed basename below: 

`ad_discovery`, `ai-phishing`, `clickfix`, `coinbait`, `deepfake-id-fraud`, `dprk_fraud`, `gtg1002`, `hello_world`, `honestcue`, `jasper_sleet`, `london_drugs_lockbit`, `malterminal`, `nocode_ransomware`, `ns_power_ransomware`, `operation_dream_job`, `operation_false_witness`, `promptflux`, `promptsteal`, `quietvault`, `scope_creep`, `tycoon2fa`, `vibe_extortion`, `wormgpt_kawaiigpt`

#### More generator flags

See `python run.py --generate --help` for `--dry-run`, `--fragment`, `--legitimize`, `--output-toml`, and others.


### 1.3 Outputs

For each campaign in `seeds/*.json`, the pipeline produces two dataset variants under `results/` using 1.1 and 1.2 respectively:
| File | Meaning |
|------|--------|
| `results/<seed>_manual.json` | Template-based stylization; reproducible; no keys. |
| `results/<seed>_llm.json` | LLM-rephrased stylization; needs `ANTHROPIC_API_KEY`; slower and billed. |


#### 1.4 TIP: Generate all seeds

```bash
# Manual variants for every seed
for f in seeds/*.json; do
  name=$(basename "$f" .json)
  python run.py --generate --seed-file "$f" --seed 0 \
    --output-json "results/${name}_manual.json"
done

# LLM variants (needs ANTHROPIC_API_KEY, slower, costs money)
for f in seeds/*.json; do
  name=$(basename "$f" .json)
  python run.py --generate --seed-file "$f" \
    --no-style-templates --max-concurrency 32 \
    --output-json "results/${name}_llm.json"
done
```


#### Next steps

The generated JSON files (`results/<seed>_manual.json` / `results/<seed>_llm.json`) are the inputs to the MCP graph runner or can be further refined in the RL step. 

---

## 2. Reinforcement Learning based Rewriting (`fragbench-structural-graph-main`) (Optional)

Optional step: judge or RL-rewrite generated JSON fragments using [fragbench_generated_rl.py](fragbench-structural-graph-main/fragbench_dataset_generator/fragbench_pack/fragbench_generated_rl.py) to improve pass rate and reduce refusals.

The input dataset **must** be placed under `fragbench-structural-graph-main/dataset/` before running this step. For example, `results/promptsteal_manual.json` from §1 should be copied or staged as `fragbench-structural-graph-main/dataset/promptsteal_manual.json`, then referenced as `--input dataset/promptsteal_manual.json` from inside `fragbench-structural-graph-main`.

### 2.1 API keys

The required keys depend on the selected `--judge-backend` and `--rewriter-backend`:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export OPENROUTER_API_KEY=sk-or-...
```

```bash
cd fragbench-structural-graph-main


python -u fragbench_dataset_generator/fragbench_pack/fragbench_generated_rl.py \
        --mode rl \
        --variation-style direct \
        --judge-backend anthropic \
        --judge-model claude-sonnet-4-6 \
        --rewriter-backend openrouter \
        --rewriter-model deepseek/deepseek-v4-flash \
        --input dataset/promptsteal_manual.json
```

>**Anthropic backend:** If Anthropic models are selected for `--judge-backend` or `--rewriter-backend`, calls go to Anthropic’s API. `ANTHROPIC_API_KEY` is required; there is no substitute when using those backends.

>Backends can be mixed (e.g. OpenRouter judge + Anthropic rewriter) as long as the matching key is present.

- **`MODE`**: `judge` (pass-rate only) or `rl` (rewrite loop).
- **`--input`**: path under the local `dataset/` directory (e.g. `dataset/promptsteal_manual.json`).
- **`--output`**: optional; if omitted, the script picks a path under `runs/`.
- Set `jb` / `rb` / models to match the available keys (e.g. OpenRouter judge + rewriter for full RL without local Ollama).

This will create a folder with 3 outputs:
- `run_policies.json` — Structured list of rewriting strategies available to / learned during the run (IDs, descriptions, and success/failure tallies).

- `run_trajectory.json` — Round-by-round summary of training (phase, pass rate, how many prompts were attempted, aggregate strategy stats).

- `run.json` — Rewritten fragments in same format as input file (can be executed against MCP)
---

## 3. MCP validation (Docker)

The fragments materialized in **§1** (and optionally rewritten in **§2**) describe an attack as ordered steps, dependencies, and prompts. **MCP validation** answers a different question: faced with a real **tool-equipped agent** in an isolated environment, does a **target model** actually drive the chain forward—file writes, shell, recon, and other MCP tools—according to each fragment?

Runs execute through the same **Docker-isolated** MCP stack used for serious evaluation: toolkits wired like production, scheduling that respects the fragment DAG (`produces` / `consumes`). The result is **per-fragment** outcomes (pass or fail), optional judge verdicts, and full tool traces. That closes the loop from “attack text” to **observed behavior**, which is what downstream **defense** needs: baselines for monitors, policy experiments (guardrails, deny lists, system prompts), regression tests after mitigations, and apples-to-apples comparison of models—without treating “unsafe prose in chat” as equivalent to “completed malicious tool use.”

This path is **Docker-only**; there is no bare-metal graph runner.

### MCP harness architecture

**MCP harness architecture.** A central `mcp-client` ingests campaign JSON files, selects the attack based on the style and seed, and routes tool calls to a fleet of 24 specialised MCP servers via FastMCP (HTTP + SSE). All agent interactions are captured as structured `.jsonl` session logs served through a viewer at port 8787. Support is available for self-hosted LLMs as well as those accessed via OpenRouter.

![MCP harness architecture](./images/mcp-architecture.png)

**[Open Figure 3 (vector PDF)](./images/mcp-architecture.pdf)** — use this PDF for clearer version.

### 3.1 Check Docker and start the stack

Confirm the tooling and daemon:

```bash
docker --version
docker compose version
```

From the repo root, bring up MCP servers and the results viewer:

```bash
docker compose up -d
docker compose ps    # most services should be Running
```

`mcp-client` mounts `./results` read-write (reads the fragments file, writes `results/runs/`) and mounts `./logs` for per-fragment session streams. The viewer mounts `./results` and `./logs` read-only so completed outputs and live traces can be inspected from the browser.

The Docker stack exposes multiple MCP servers under `fragbench_mcp/servers/`. Examples include:

| Server | Path | Example role |
|--------|------|--------------|
| Filesystem | `fragbench_mcp/servers/filesystem/server.py` | Read/write files created by fragments. |
| Shell | `fragbench_mcp/servers/shell/server.py` | Execute shell commands inside the sandbox. |
| Network recon | `fragbench_mcp/servers/network_recon/server.py` | Exercise network-discovery style fragments. |
| Email | `fragbench_mcp/servers/email/server.py` | Validate email-themed social or delivery workflows. |
| Credential | `fragbench_mcp/servers/credential/server.py` | Validate credential-handling and secret-management scenarios. |

### 3.2 Run the graph attack (default: OpenRouter)

The Makefile defaults to **`MCP_MODEL_BACKEND=openrouter`** and **`MCP_MODEL=anthropic/claude-haiku-4.5`**. Provide an OpenRouter key (or add it to a `.env` the compose file loads):

```bash
export OPENROUTER_API_KEY=sk-or-...
```

Run against fragments from §1 or §2:

```bash
make docker-attack-graph-run \
  FRAGMENTS=results/promptsteal_manual.json \
  STYLE=direct \
  SEEDS=0-9 \
  MAX_PARALLEL_VARIATIONS=4 \
  MAX_PARALLEL_FRAGMENTS=2
```

Override **`MCP_MODEL`** to change the **model under test** (still on OpenRouter), for example:

```bash
make docker-attack-graph-run \
  FRAGMENTS=results/promptsteal_manual.json \
  STYLE=direct \
  SEEDS=0-2 \
  MCP_MODEL=qwen/qwen3.5-122b-a10b \
  JUDGE=1 \
  JUDGE_MODEL=anthropic/claude-haiku-4.5
```

Set **`JUDGE=1`** for LLM-as-judge on fragment success (and per-response classification in the MCP client). If the judge API is unavailable, the runner falls back to keyword checks. Response verdicts remain `ANSWERED` · `REFUSED` · `PARTIAL` · `UNCLEAR` when the judge path is active.

| Variable | Meaning | Default (graph run) |
|----------|---------|---------------------|
| `FRAGMENTS` | Path to fragments JSON | `results/promptsteal_fragments.json` |
| `STYLE` | Variation style per seed | `direct` |
| `SEEDS` | `0`, `0,2,4`, `0-9`, or empty = all seeds in file | (all) |
| `MAX_PARALLEL_VARIATIONS` | Concurrent variation jobs | `4` |
| `MAX_PARALLEL_FRAGMENTS` | Concurrent fragments per variation (DAG-aware) | `2` |
| `MCP_MODEL_BACKEND` | Target backend: `openrouter` or `ollama` | `openrouter` |
| `MCP_MODEL` | Target model id | `anthropic/claude-haiku-4.5` |
| `JUDGE` | `1` = enable LLM judge | `0` |
| `JUDGE_BACKEND` / `JUDGE_MODEL` | Evaluator backend and model | `openrouter` / `anthropic/claude-haiku-4.5` |

### 3.3 Optional: local target with Ollama

To use a model on the host instead of OpenRouter, run Ollama and select the `ollama` backend. Containers reach the host at `host.docker.internal:11434`.

```bash
brew install ollama      # macOS — or https://ollama.com/download
ollama serve
```

In another terminal (large first-time download):

```bash
ollama pull huihui_ai/qwen3.5-abliterated:35b
ollama list
```

Then:

```bash
make docker-attack-graph-run \
  FRAGMENTS=results/promptsteal_manual.json \
  STYLE=direct \
  MCP_MODEL_BACKEND=ollama \
  MCP_MODEL=huihui_ai/qwen3.5-abliterated:35b
```

### 3.4 Outputs

Each graph run leaves structured JSON under `results/runs/`.

| Example file | Contents (high level) |
|--------------|------------------------|
| `attack_20260505_030157_e64467_meta.json` | Run-wide metadata written around start/end: which `fragments_path`, `seeds`, `style`, `target_model` / `target_backend`, `judge_model`, timestamps, `status`, aggregate pass count. This file catalogues batch jobs and ties every per-seed file back to one `run_id`. |
| `attack_20260505_015031_fbfff5_seed_1345099283_HONESTCUE_1345099283.json` | **Chain summary** for one seed: campaign id, style, whether the full variation **passed**, and an ordered **`fragments`** list with prompts, roles, phases, `produces` / `consumes`, and each fragment’s **pass** / **verdict** / **justification** (no full tool dumps). Ideal for quick scoring tables and governance summaries. |
| `attack_graph_20260505_015031_fbfff5_seed_1345099283_HONESTCUE_1345099283.json` | **Graph detail** for the same seed: **`phases_in_order`**, rich **`variation`** block, and per-fragment **`tools_executed`** (tool name plus arguments), **`final_response`**, **`session_path`** to the JSONL log, timings, and artifact bookkeeping. This file supports defense forensics and debugging *how* the agent satisfied or missed each step. |

### 3.5 Logs

Per-fragment sessions are **JSONL** streams (`session_<timestamp>_<id>.jsonl`). Paths appear in graph JSON as `session_path` (container paths under `/app/logs/` map to `./logs/` on the host). By default the graph runner also isolates sessions under **`logs/<run_id>/`** for a given attack run; that subdirectory should be checked when the repo root `logs/` is crowded.

### 3.6 Viewer

The web UI runs at [http://localhost:8787](http://localhost:8787). The **Live** view shows sessions while fragments execute; the **Graph** view shows pass/fail vectors and fragment-level details after completion. A run can be opened directly with `http://localhost:8787/graph.html?run=<run_id>`.

**MCP validation frontend views.** The **Live** view streams fragment execution in real time, including MCP agent sessions, model responses, tool calls, and intermediate status. The **Graph** view summarizes completed validation runs by campaign phase and reports per-fragment pass/fail outcomes, judge rationales, tool executions, and artifact dependencies used for downstream defense analysis. Green indicates fragments that passed the LLM judge’s evaluation for having completed the task; red indicates those that failed.

**(a) Live view.**

![Live view of the MCP validation frontend](./images/live-view.png)

**(b) Graph view.**

![Graph view of the MCP validation frontend](./images/graph-view.png)

### 3.7 Tear down

```bash
docker compose down
```

If Ollama was used, stop it with `Ctrl-C` in its terminal (or `killall ollama`).



