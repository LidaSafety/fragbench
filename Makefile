SHELL := /bin/bash

UV ?= uv run
PY ?= python3

MODEL_BACKEND ?= openrouter
# Host Ollama (reachable from Docker via host.docker.internal on Mac/Windows Desktop)
OLLAMA_BASE_URL ?= http://host.docker.internal:11434
VLLM_BASE_URL ?= http://127.0.0.1:8000/v1
VLLM_API_KEY ?= EMPTY
ATTACK_SEED ?= seeds/hello_world.json
ATTACK_VARIATION_SEED ?= 42
ATTACK_STAGE ?= 0
REGISTRY_PATH ?= fragbench_mcp/registry/toolkits.toml
EXEC_MODE ?= simulated
LOG_DIR ?= logs

PID_DIR := .mcp-run
SERVER_LOG_DIR := $(PID_DIR)/logs
TOOLKIT_ENDPOINTS := http://127.0.0.1:8001/mcp http://127.0.0.1:8011/mcp http://127.0.0.1:8012/mcp http://127.0.0.1:8013/mcp http://127.0.0.1:8014/mcp

ifeq ($(MODEL_BACKEND),ollama)
MODEL ?= huihui_ai/qwen3.5-abliterated:35b
else ifeq ($(MODEL_BACKEND),vllm)
MODEL ?= huihui-ai/Huihui-Qwen3.5-35B-A3B-abliterated
else
MODEL ?= anthropic/claude-haiku-4.5
endif

FS_PID := $(PID_DIR)/filesystem.pid
SHELL_PID := $(PID_DIR)/shell.pid
ARCHIVE_PID := $(PID_DIR)/archive.pid
EXFIL_PID := $(PID_DIR)/exfil.pid
NETWORK_PID := $(PID_DIR)/network.pid

FS_URL := http://127.0.0.1:8001/mcp
SHELL_URL := http://127.0.0.1:8011/mcp
ARCHIVE_URL := http://127.0.0.1:8012/mcp
EXFIL_URL := http://127.0.0.1:8013/mcp
NETWORK_URL := http://127.0.0.1:8014/mcp

.PHONY: help stack-up stack-down stack-status stack-ready maple-check maple-ready cli hello-run attack-run chain-run clean-runtime

help:
	@echo "Targets (bare-metal):"
	@echo "  make stack-up       - Start all MCP toolkit servers"
	@echo "  make stack-down     - Stop all MCP toolkit servers"
	@echo "  make stack-status   - Show server process status"
	@echo "  make stack-ready    - Start stack and verify status"
	@echo "  make maple-check    - Preflight checks for maple/backends/endpoints"
	@echo "  make maple-ready    - Start stack then run maple-check"
	@echo "  make cli            - Run interactive MCP CLI (auto toolkits)"
	@echo "  make hello-run      - Generate hello prompt and run one-shot CLI"
	@echo "  make attack-run     - Generate attack prompt from ATTACK_SEED and run one-shot CLI"
	@echo "  make chain-run      - Run ALL stages of ATTACK_SEED sequentially with shared run-id"
	@echo "  make clean-runtime  - Remove pid/log runtime artifacts"
	@echo ""
	@echo "Targets (Docker-isolated):"
	@echo "  make docker-up         - Start MCP servers + viewer in containers"
	@echo "  make docker-down       - Stop all containers"
	@echo "  make docker-status     - Show container status"
	@echo "  make docker-cli        - Interactive MCP CLI inside container"
	@echo "  make docker-attack-run - Single-stage attack in container"
	@echo "  make docker-chain-run  - Full kill-chain in container (all stages)"
	@echo ""
	@echo "Targets (Docker dataset pipeline - TOML generation + eval):"
	@echo "  make docker-dataset-up                  - Reminder: host Ollama at host.docker.internal:11434"
	@echo "  make docker-dataset-down                - Stop dataset profile containers"
	@echo "  make docker-dataset-validate-seed       - Validate ATTACK_SEED + VARIATION_REGISTRY wiring"
	@echo "  make docker-dataset-generate            - Generate TOMLs (no rewriting)"
	@echo "  make docker-dataset-generate-fragment   - Generate TOMLs with --fragment (via Ollama)"
	@echo "  make docker-dataset-generate-legitimize - Generate TOMLs with --legitimize (via Ollama)"
	@echo "  make docker-dataset-generate-frag-legit - Generate TOMLs with --fragment --legitimize (via Ollama)"
	@echo "  make docker-attacks-list                - List generated TOMLs"
	@echo "  make docker-attacks-show                - Print one TOML (ATTACK_TOML=...)"
	@echo "  make docker-dataset-eval-qwen           - Evaluate attacks/*.toml using Qwen"
	@echo "  make docker-dataset-eval-claude         - Evaluate attacks/*.toml using Claude"
	@echo "  make docker-dataset-eval-judge          - Evaluate using Qwen/Claude + LLM judge"
	@echo ""
	@echo "Config overrides (both bare-metal and Docker):"
	@echo "  MODEL_BACKEND=$(MODEL_BACKEND) MODEL=$(MODEL) EXEC_MODE=$(EXEC_MODE)"
	@echo "  OLLAMA_BASE_URL=$(OLLAMA_BASE_URL) VLLM_BASE_URL=$(VLLM_BASE_URL)"
	@echo "  ATTACK_SEED=$(ATTACK_SEED) ATTACK_VARIATION_SEED=$(ATTACK_VARIATION_SEED) ATTACK_STAGE=$(ATTACK_STAGE)"
	@echo "  REGISTRY_PATH=$(REGISTRY_PATH)"
	@echo ""
	@echo "Dataset config (Docker TOML pipeline):"
	@echo "  DATASET_N=$(DATASET_N) DATASET_BASE_SEED=$(DATASET_BASE_SEED) ATTACKS_DIR=$(ATTACKS_DIR)"
	@echo "  GEN_BACKEND=$(GEN_BACKEND) GEN_MODEL=$(GEN_MODEL) GEN_BASE_URL=$(GEN_BASE_URL)"

$(PID_DIR):
	@mkdir -p "$(PID_DIR)" "$(SERVER_LOG_DIR)"

define URL_IS_REACHABLE
	@$(PY) -c 'import socket,sys; from urllib.parse import urlparse; u=urlparse(sys.argv[1]); host=u.hostname or "127.0.0.1"; port=u.port or 80; s=socket.socket(); s.settimeout(1.5); s.connect((host,port)); s.close()' "$(1)" >/dev/null 2>&1
endef

define START_IF_NEEDED
	@if $(PY) -c 'import socket,sys; from urllib.parse import urlparse; u=urlparse(sys.argv[1]); host=u.hostname or "127.0.0.1"; port=u.port or 80; s=socket.socket(); s.settimeout(1.5); code=s.connect_ex((host,port)); s.close(); sys.exit(0 if code==0 else 1)' "$(1)" >/dev/null 2>&1; then \
		echo "Already running $(2) at $(1)"; \
	else \
		echo "Starting $(2) at $(1)..."; \
		nohup $(UV) $(PY) $(3) > "$(4)" 2>&1 & echo $$! > "$(5)"; \
	fi
endef

stack-up: $(PID_DIR)
	$(call START_IF_NEEDED,$(FS_URL),filesystem,fragbench_mcp/servers/filesystem_server.py --transport sse --port 8001,$(SERVER_LOG_DIR)/filesystem.log,$(FS_PID))
	$(call START_IF_NEEDED,$(SHELL_URL),shell,fragbench_mcp/servers/shell_server.py --transport sse --port 8011,$(SERVER_LOG_DIR)/shell.log,$(SHELL_PID))
	$(call START_IF_NEEDED,$(ARCHIVE_URL),archive,fragbench_mcp/servers/archive_server.py --transport sse --port 8012,$(SERVER_LOG_DIR)/archive.log,$(ARCHIVE_PID))
	$(call START_IF_NEEDED,$(EXFIL_URL),exfil,fragbench_mcp/servers/exfil_server.py --transport sse --port 8013,$(SERVER_LOG_DIR)/exfil.log,$(EXFIL_PID))
	$(call START_IF_NEEDED,$(NETWORK_URL),network,fragbench_mcp/servers/network_recon_server.py --transport sse --port 8014,$(SERVER_LOG_DIR)/network.log,$(NETWORK_PID))
	@sleep 2
	@$(MAKE) stack-status

define CHECK_PID
	@if [ -f "$(1)" ]; then \
		pid=$$(cat "$(1)"); \
		if kill -0 $$pid >/dev/null 2>&1; then \
			echo "OK   $${pid}  $(2)"; \
		else \
			echo "DOWN $${pid}  $(2)"; \
		fi; \
	else \
		echo "MISS ----  $(2)"; \
	fi
endef

define CHECK_ENDPOINT
	@if $(PY) -c 'import socket,sys; from urllib.parse import urlparse; u=urlparse(sys.argv[1]); host=u.hostname or "127.0.0.1"; port=u.port or 80; s=socket.socket(); s.settimeout(1.5); code=s.connect_ex((host,port)); s.close(); sys.exit(0 if code==0 else 1)' "$(1)" >/dev/null 2>&1; then \
		echo "UP   ----  $(2)"; \
	else \
		echo "DOWN ----  $(2)"; \
	fi
endef

stack-status:
	@echo "Server endpoint status:"
	$(call CHECK_ENDPOINT,$(FS_URL),filesystem:8001)
	$(call CHECK_ENDPOINT,$(SHELL_URL),shell:8011)
	$(call CHECK_ENDPOINT,$(ARCHIVE_URL),archive:8012)
	$(call CHECK_ENDPOINT,$(EXFIL_URL),exfil:8013)
	$(call CHECK_ENDPOINT,$(NETWORK_URL),network:8014)

define STOP_PID
	@if [ -f "$(1)" ]; then \
		pid=$$(cat "$(1)"); \
		if kill -0 $$pid >/dev/null 2>&1; then \
			echo "Stopping $(2) ($$pid)"; \
			kill $$pid >/dev/null 2>&1 || true; \
		fi; \
		rm -f "$(1)"; \
	fi
endef

stack-down:
	$(call STOP_PID,$(FS_PID),filesystem)
	$(call STOP_PID,$(SHELL_PID),shell)
	$(call STOP_PID,$(ARCHIVE_PID),archive)
	$(call STOP_PID,$(EXFIL_PID),exfil)
	$(call STOP_PID,$(NETWORK_PID),network)

stack-ready: stack-up
	@echo "MCP stack is ready."

maple-check:
	@echo "Running maple preflight checks..."
	@command -v uv >/dev/null 2>&1 || (echo "ERROR: uv not found in PATH"; exit 1)
	@command -v $(PY) >/dev/null 2>&1 || (echo "ERROR: $(PY) not found in PATH"; exit 1)
	@[ -f "$(ATTACK_SEED)" ] || (echo "ERROR: ATTACK_SEED file not found: $(ATTACK_SEED)"; exit 1)
	@[ -f "$(REGISTRY_PATH)" ] || (echo "ERROR: REGISTRY_PATH file not found: $(REGISTRY_PATH)"; exit 1)
	@if [ "$(MODEL_BACKEND)" = "openrouter" ]; then \
		[ -n "$$OPENROUTER_API_KEY" ] || (echo "ERROR: OPENROUTER_API_KEY is required for MODEL_BACKEND=openrouter"; exit 1); \
	fi
	@if [ "$(MODEL_BACKEND)" = "ollama" ]; then \
		URL="$(OLLAMA_BASE_URL)"; \
		$(PY) -c 'import socket,sys; from urllib.parse import urlparse; u=urlparse(sys.argv[1]); host=u.hostname or "127.0.0.1"; port=u.port or 80; s=socket.socket(); s.settimeout(2); s.connect((host,port)); s.close(); print(f"OK: ollama reachable at {host}:{port}")' "$$URL" || \
		(echo "ERROR: Ollama endpoint unreachable: $(OLLAMA_BASE_URL)"; exit 1); \
		$(PY) -c 'import sys,urllib.request; base=sys.argv[1].rstrip("/"); url=f"{base}/api/tags"; r=urllib.request.urlopen(url, timeout=3); print(f"OK: ollama API responds at {url} (status={r.getcode()})")' "$$URL" || \
		(echo "ERROR: Ollama API did not respond at /api/tags; check base URL/version"; exit 1); \
		$(PY) -c 'import json,sys,urllib.request; base=sys.argv[1].rstrip("/"); model=sys.argv[2]; data=json.load(urllib.request.urlopen(f"{base}/api/tags", timeout=3)); names={m.get("name","") for m in data.get("models",[])}; \
ok=(model in names) or any(str(n).startswith(model + ":") for n in names); \
print(f"OK: ollama model available: {model}" if ok else f"MISSING: ollama model {model}. Available: {sorted(names)[:20]}"); \
raise SystemExit(0 if ok else 1)' "$$URL" "$(MODEL)" || \
		(echo "ERROR: Requested MODEL not found in Ollama. Run: ollama pull $(MODEL)"; exit 1); \
	fi
	@if [ "$(MODEL_BACKEND)" = "vllm" ]; then \
		URL="$(VLLM_BASE_URL)"; \
		$(PY) -c 'import socket,sys; from urllib.parse import urlparse; u=urlparse(sys.argv[1]); host=u.hostname or "127.0.0.1"; port=u.port or 80; s=socket.socket(); s.settimeout(2); s.connect((host,port)); s.close(); print(f"OK: vLLM reachable at {host}:{port}")' "$$URL" || \
		(echo "ERROR: vLLM endpoint unreachable: $(VLLM_BASE_URL)"; exit 1); \
	fi
	@for URL in $(TOOLKIT_ENDPOINTS); do \
		$(PY) -c 'import socket,sys; from urllib.parse import urlparse; u=urlparse(sys.argv[1]); host=u.hostname or "127.0.0.1"; port=u.port or 80; s=socket.socket(); s.settimeout(2); s.connect((host,port)); s.close()' "$$URL" || \
		(echo "ERROR: toolkit endpoint unreachable: $$URL (start with: make stack-ready)"; exit 1); \
		echo "OK: toolkit endpoint reachable $$URL"; \
	done
	@echo "Maple preflight checks passed."

maple-ready: stack-ready maple-check
	@echo "Maple stack is ready for attack runs."

cli:
	@$(UV) $(PY) fragbench_mcp/mcp_cli.py \
		--model-backend "$(MODEL_BACKEND)" \
		--model "$(MODEL)" \
		--ollama-base-url "$(OLLAMA_BASE_URL)" \
		--vllm-base-url "$(VLLM_BASE_URL)" \
		--vllm-api-key "$(VLLM_API_KEY)" \
		--auto-toolkits \
		--registry-path "$(REGISTRY_PATH)" \
		--attack-seed "$(ATTACK_SEED)" \
		--execution-mode "$(EXEC_MODE)" \
		--log-dir "$(LOG_DIR)"

hello-run:
	@PROMPT="$$( $(UV) $(PY) -c 'from variations.hello_world import HelloWorldVariation; p,_=HelloWorldVariation("seeds/hello_world.json").make_variation(seed=42)[0]; print(p)' )"; \
	echo "Prompt: $$PROMPT"; \
	$(UV) $(PY) fragbench_mcp/mcp_cli.py \
		--model-backend "$(MODEL_BACKEND)" \
		--model "$(MODEL)" \
		--ollama-base-url "$(OLLAMA_BASE_URL)" \
		--vllm-base-url "$(VLLM_BASE_URL)" \
		--vllm-api-key "$(VLLM_API_KEY)" \
		--auto-toolkits \
		--registry-path "$(REGISTRY_PATH)" \
		--attack-seed "$(ATTACK_SEED)" \
		--execution-mode "$(EXEC_MODE)" \
		--log-dir "$(LOG_DIR)" \
		--prompt "$$PROMPT"

RUN_ID ?=
ATTACK_ID_OVERRIDE ?=

attack-run: stack-ready
	@PROMPT="$$( $(UV) $(PY) -c 'import json; from pathlib import Path; from generator import VARIATION_REGISTRY; seed_file=Path("$(ATTACK_SEED)"); data=json.loads(seed_file.read_text()); key=str(data.get("metadata",{}).get("id","")).lower(); cls=VARIATION_REGISTRY.get(key); assert cls is not None, f"No variation registered for {key}"; gen=cls(str(seed_file)); detailed=gen.make_variation_detailed(seed=int("$(ATTACK_VARIATION_SEED)")); idx=max(0,min(int("$(ATTACK_STAGE)"), len(detailed)-1)); print(detailed[idx]["prompt"])' )"; \
	ATTACK_ID="$${ATTACK_ID_OVERRIDE:-$$( $(UV) $(PY) -c 'import json; data=json.loads(open("$(ATTACK_SEED)").read()); print(data.get("metadata",{}).get("id","UNKNOWN"))' )}"; \
	echo "Seed: $(ATTACK_SEED) | variation-seed: $(ATTACK_VARIATION_SEED) | stage: $(ATTACK_STAGE)"; \
	echo "Prompt: $$PROMPT"; \
	$(UV) $(PY) fragbench_mcp/mcp_cli.py \
		--model-backend "$(MODEL_BACKEND)" \
		--model "$(MODEL)" \
		--ollama-base-url "$(OLLAMA_BASE_URL)" \
		--vllm-base-url "$(VLLM_BASE_URL)" \
		--vllm-api-key "$(VLLM_API_KEY)" \
		--auto-toolkits \
		--registry-path "$(REGISTRY_PATH)" \
		--attack-seed "$(ATTACK_SEED)" \
		--execution-mode "$(EXEC_MODE)" \
		--log-dir "$(LOG_DIR)" \
		$${RUN_ID:+--run-id "$(RUN_ID)"} \
		--campaign "$$ATTACK_ID" \
		--attack-id "$$ATTACK_ID" \
		--prompt "$$PROMPT"

chain-run: stack-ready
	@RUN_ID="chain_$$(date +%Y%m%d_%H%M%S)"; \
	ATTACK_ID="$$( $(UV) $(PY) -c 'import json; data=json.loads(open("$(ATTACK_SEED)").read()); print(data.get("metadata",{}).get("id","UNKNOWN"))' )"; \
	NUM_STAGES="$$( $(UV) $(PY) -c 'import json; data=json.loads(open("$(ATTACK_SEED)").read()); print(len(data.get("attack_stages",[])))' )"; \
	echo ""; \
	echo "╔══════════════════════════════════════════════════════════════╗"; \
	echo "║  CHAIN RUN: $$ATTACK_ID"; \
	echo "║  Stages: $$NUM_STAGES | Variation seed: $(ATTACK_VARIATION_SEED) | Run ID: $$RUN_ID"; \
	echo "╚══════════════════════════════════════════════════════════════╝"; \
	echo ""; \
	for STAGE in $$(seq 0 $$((NUM_STAGES - 1))); do \
		echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; \
		echo "  Stage $$STAGE / $$((NUM_STAGES - 1))"; \
		echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; \
		$(MAKE) --no-print-directory attack-run \
			ATTACK_SEED="$(ATTACK_SEED)" \
			ATTACK_VARIATION_SEED="$(ATTACK_VARIATION_SEED)" \
			ATTACK_STAGE="$$STAGE" \
			MODEL_BACKEND="$(MODEL_BACKEND)" \
			MODEL="$(MODEL)" \
			RUN_ID="$$RUN_ID" \
			ATTACK_ID_OVERRIDE="$$ATTACK_ID" \
			LOG_DIR="$(LOG_DIR)"; \
		echo ""; \
	done; \
	echo "╔══════════════════════════════════════════════════════════════╗"; \
	echo "║  CHAIN COMPLETE: $$ATTACK_ID | $$NUM_STAGES stages"; \
	echo "║  Run ID: $$RUN_ID"; \
	echo "║  View: http://127.0.0.1:8787 → Load Latest or select run"; \
	echo "╚══════════════════════════════════════════════════════════════╝"

clean-runtime:
	@rm -rf "$(PID_DIR)"

# =========================================================================
# Docker-isolated equivalents
# =========================================================================
#
# These targets run inside Docker containers with full network isolation.
# Prerequisite: docker compose up -d  (starts MCP servers + viewer)
#
# Config overrides work the same way:
#   make docker-chain-run ATTACK_SEED=seeds/promptsteal.json MODEL_BACKEND=ollama ATTACK_VARIATION_SEED=99
# =========================================================================

DOCKER_COMPOSE ?= docker compose
DOCKER_REGISTRY_PATH ?= fragbench_mcp/registry/toolkits.toml
DOCKER_OLLAMA_URL ?= http://host.docker.internal:11434
DOCKER_VLLM_URL ?= http://host.docker.internal:8000/v1

.PHONY: docker-up docker-down docker-status docker-cli docker-attack-run docker-chain-run

docker-up:
	@$(DOCKER_COMPOSE) up -d
	@echo "MCP servers + viewer running. Viewer: http://localhost:8787"

docker-down:
	@$(DOCKER_COMPOSE) down

docker-status:
	@$(DOCKER_COMPOSE) ps

define DOCKER_CLIENT_CMD
EFFECTIVE_MODEL="$(MODEL)"; \
if [ "$(MODEL_BACKEND)" = "ollama" ]; then \
  case "$$EFFECTIVE_MODEL" in *:*) ;; *) EFFECTIVE_MODEL="huihui_ai/qwen3.5-abliterated:35b";; esac; \
fi; \
$(DOCKER_COMPOSE) run --rm \
	-e OPENROUTER_API_KEY \
	-e OPENAI_API_KEY \
	-e OLLAMA_BASE_URL="$(DOCKER_OLLAMA_URL)" \
	-e VLLM_BASE_URL="$(DOCKER_VLLM_URL)" \
	mcp-client \
		--model-backend "$(MODEL_BACKEND)" \
		--model "$$EFFECTIVE_MODEL" \
		--auto-toolkits \
		--registry-path "$(DOCKER_REGISTRY_PATH)" \
		--attack-seed "$(ATTACK_SEED)" \
		--execution-mode "$(EXEC_MODE)" \
		--log-dir "$(LOG_DIR)"
endef

docker-cli: docker-up
	$(DOCKER_CLIENT_CMD)

docker-attack-run: docker-up
	@PROMPT="$$( $(PY) -c 'import json; from pathlib import Path; from generator import VARIATION_REGISTRY; seed_file=Path("$(ATTACK_SEED)"); data=json.loads(seed_file.read_text()); key=str(data.get("metadata",{}).get("id","")).lower(); cls=VARIATION_REGISTRY.get(key); assert cls is not None, f"No variation registered for {key}"; gen=cls(str(seed_file)); detailed=gen.make_variation_detailed(seed=int("$(ATTACK_VARIATION_SEED)")); idx=max(0,min(int("$(ATTACK_STAGE)"), len(detailed)-1)); print(detailed[idx]["prompt"])' )"; \
	ATTACK_ID="$${ATTACK_ID_OVERRIDE:-$$( $(PY) -c 'import json; data=json.loads(open("$(ATTACK_SEED)").read()); print(data.get("metadata",{}).get("id","UNKNOWN"))' )}"; \
	EFFECTIVE_MODEL="$(MODEL)"; \
	if [ "$(MODEL_BACKEND)" = "ollama" ]; then \
	  case "$$EFFECTIVE_MODEL" in *:*) ;; *) EFFECTIVE_MODEL="huihui_ai/qwen3.5-abliterated:35b";; esac; \
	fi; \
	echo "Seed: $(ATTACK_SEED) | variation-seed: $(ATTACK_VARIATION_SEED) | stage: $(ATTACK_STAGE)"; \
	echo "Prompt: $$PROMPT"; \
	$(DOCKER_COMPOSE) run --rm \
		-e OPENROUTER_API_KEY \
		-e OPENAI_API_KEY \
		-e OLLAMA_BASE_URL="$(DOCKER_OLLAMA_URL)" \
		-e VLLM_BASE_URL="$(DOCKER_VLLM_URL)" \
		mcp-client \
			--model-backend "$(MODEL_BACKEND)" \
			--model "$$EFFECTIVE_MODEL" \
			--auto-toolkits \
			--registry-path "$(DOCKER_REGISTRY_PATH)" \
			--attack-seed "$(ATTACK_SEED)" \
			--execution-mode "$(EXEC_MODE)" \
			--log-dir "$(LOG_DIR)" \
			$${RUN_ID:+--run-id "$(RUN_ID)"} \
			--campaign "$$ATTACK_ID" \
			--attack-id "$$ATTACK_ID" \
			--prompt "$$PROMPT"

docker-chain-run: docker-up
	@RUN_ID="chain_$$(date +%Y%m%d_%H%M%S)"; \
	ATTACK_ID="$$( $(PY) -c 'import json; data=json.loads(open("$(ATTACK_SEED)").read()); print(data.get("metadata",{}).get("id","UNKNOWN"))' )"; \
	NUM_STAGES="$$( $(PY) -c 'import json; data=json.loads(open("$(ATTACK_SEED)").read()); print(len(data.get("attack_stages",[])))' )"; \
	echo ""; \
	echo "╔══════════════════════════════════════════════════════════════╗"; \
	echo "║  DOCKER CHAIN RUN: $$ATTACK_ID"; \
	echo "║  Stages: $$NUM_STAGES | Variation seed: $(ATTACK_VARIATION_SEED) | Run ID: $$RUN_ID"; \
	echo "╚══════════════════════════════════════════════════════════════╝"; \
	echo ""; \
	for STAGE in $$(seq 0 $$((NUM_STAGES - 1))); do \
		echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; \
		echo "  Stage $$STAGE / $$((NUM_STAGES - 1))"; \
		echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; \
		$(MAKE) --no-print-directory docker-attack-run \
			ATTACK_SEED="$(ATTACK_SEED)" \
			ATTACK_VARIATION_SEED="$(ATTACK_VARIATION_SEED)" \
			ATTACK_STAGE="$$STAGE" \
			MODEL_BACKEND="$(MODEL_BACKEND)" \
			MODEL="$(MODEL)" \
			RUN_ID="$$RUN_ID" \
			ATTACK_ID_OVERRIDE="$$ATTACK_ID" \
			LOG_DIR="$(LOG_DIR)"; \
		echo ""; \
	done; \
	echo "╔══════════════════════════════════════════════════════════════╗"; \
	echo "║  CHAIN COMPLETE: $$ATTACK_ID | $$NUM_STAGES stages"; \
	echo "║  Run ID: $$RUN_ID"; \
	echo "║  View: http://127.0.0.1:8787 → Load Latest or select run"; \
	echo "╚══════════════════════════════════════════════════════════════╝"

# -------------------------------------------------------------------------
# Docker: Run TOML prompts as MCP stages (Option B)
# -------------------------------------------------------------------------
#
# Treat each TOML variation prompt as a stage prompt and run `mcp-client` once
# per prompt. This is *not* the same as evaluating TOMLs via `run.py`; it uses
# the MCP toolkits/agent loop.
#
# Required:
#   - MCP servers up (`make docker-up`)
#   - TOMLs present under ATTACKS_DIR (default attacks/)
#

TOML_GLOB ?= $(ATTACKS_DIR)/generated_*.toml

.PHONY: docker-toml-mcp-chain-run

docker-toml-mcp-chain-run: docker-up
	@RUN_ID="toml_chain_$$(date +%Y%m%d_%H%M%S)"; \
	echo ""; \
	echo "╔══════════════════════════════════════════════════════════════╗"; \
	echo "║  DOCKER TOML→MCP CHAIN RUN"; \
	echo "║  TOMLs: $(TOML_GLOB)"; \
	echo "║  Routing seed (toolkit selection): $(ATTACK_SEED)"; \
	echo "║  Model backend: $(MODEL_BACKEND) | Model: $(MODEL)"; \
	echo "║  Run ID: $$RUN_ID"; \
	echo "╚══════════════════════════════════════════════════════════════╝"; \
	echo ""; \
	shopt -s nullglob; \
	TOMLS=( $(TOML_GLOB) ); \
	if [ $${#TOMLS[@]} -eq 0 ]; then \
		echo "ERROR: no TOMLs matched: $(TOML_GLOB)"; \
		exit 1; \
	fi; \
	for TOML in "$${TOMLS[@]}"; do \
		echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; \
		echo "  TOML: $$TOML"; \
		echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; \
		ATTACK_ID="$$( $(PY) -c 'import sys,tomllib; from pathlib import Path; d=tomllib.loads(Path(sys.argv[1]).read_text()); print((d.get("metadata") or {}).get("id","UNKNOWN"))' "$$TOML" )"; \
		$(PY) -c 'import sys,tomllib,base64; from pathlib import Path; d=tomllib.loads(Path(sys.argv[1]).read_text()); \
frags=d.get("fragments") or []; \
	vals=[str(v.get("prompt","")) for f in frags for v in (f.get("variations") or [])]; \
	vals=[p for p in vals if p and p.strip()]; \
	print("\\n".join(base64.b64encode(p.encode("utf-8")).decode("ascii") for p in vals))' "$$TOML" | while read -r B64; do \
			[ -n "$$B64" ] || continue; \
			PROMPT="$$( printf "%s" "$$B64" | (base64 --decode 2>/dev/null || base64 -D) )"; \
			[ -n "$$PROMPT" ] || continue; \
			echo "  Prompt: $${PROMPT:0:120}..."; \
			$(DOCKER_COMPOSE) run --rm \
				-e OPENROUTER_API_KEY \
				-e OPENAI_API_KEY \
				-e OLLAMA_BASE_URL="$(DOCKER_OLLAMA_URL)" \
				-e VLLM_BASE_URL="$(DOCKER_VLLM_URL)" \
				mcp-client \
					--model-backend "$(MODEL_BACKEND)" \
					--model "$(MODEL)" \
					--auto-toolkits \
					--registry-path "$(DOCKER_REGISTRY_PATH)" \
					--attack-seed "$(ATTACK_SEED)" \
					--execution-mode "$(EXEC_MODE)" \
					--log-dir "$(LOG_DIR)" \
					--run-id "$$RUN_ID" \
					--campaign "$$ATTACK_ID" \
					--attack-id "$$ATTACK_ID" \
					--prompt "$$PROMPT"; \
		done; \
		echo ""; \
	done; \
	echo "╔══════════════════════════════════════════════════════════════╗"; \
	echo "║  TOML→MCP CHAIN COMPLETE"; \
	echo "║  Run ID: $$RUN_ID"; \
	echo "║  View: http://127.0.0.1:8787 → Load Latest or select run"; \
	echo "╚══════════════════════════════════════════════════════════════╝"

# =========================================================================
# Docker: TOML dataset pipeline (generation + evaluation)
# =========================================================================

DATASET_N ?= 10
DATASET_BASE_SEED ?= 1000
ATTACKS_DIR ?= attacks

# Generator LLM settings (used by run.py --generate when --fragment/--legitimize)
GEN_BACKEND ?= ollama
GEN_BASE_URL ?= http://host.docker.internal:11434

# Default GEN_MODEL depends on GEN_BACKEND (not MODEL_BACKEND)
ifeq ($(GEN_BACKEND),ollama)
GEN_MODEL ?= huihui_ai/qwen3.5-abliterated:35b
else ifeq ($(GEN_BACKEND),anthropic)
GEN_MODEL ?= claude-haiku-4.5
else
# Treat as OpenAI-compatible / OpenRouter-style model id
GEN_MODEL ?= huihui-ai/Huihui-Qwen3.5-35B-A3B-abliterated
endif

ATTACK_TOML ?=

.PHONY: docker-dataset-up docker-dataset-down docker-dataset-validate-seed \
        docker-dataset-generate docker-dataset-generate-fragment docker-dataset-generate-legitimize docker-dataset-generate-frag-legit \
        docker-attacks-list docker-attacks-show \
        docker-dataset-eval-qwen docker-dataset-eval-claude docker-dataset-eval-judge

docker-dataset-up:
	@echo "Dataset generation uses Ollama on the host (Docker → $(GEN_BASE_URL))."
	@echo "Start Ollama on the host (e.g. ollama serve) on port 11434 if not already running."

docker-dataset-down:
	@echo "Nothing to stop (Ollama runs on the host; no ollama container)."

docker-dataset-validate-seed:
	@[ -f "$(ATTACK_SEED)" ] || (echo "ERROR: ATTACK_SEED file not found: $(ATTACK_SEED)"; exit 1)
	@echo "Validating seed wiring: $(ATTACK_SEED)"
	@$(DOCKER_COMPOSE) run --rm \
		--entrypoint python dataset-runner -c 'import json; from pathlib import Path; from generator import VARIATION_REGISTRY; seed=Path("$(ATTACK_SEED)"); data=json.loads(seed.read_text()); key=str(data.get("metadata",{}).get("id","")).lower(); assert key, "seed missing metadata.id"; assert key in VARIATION_REGISTRY, f"No variation registered for {key}. Registered: {list(VARIATION_REGISTRY)}"; print(f"OK: metadata.id={key} -> {VARIATION_REGISTRY[key].__name__}")'

define DATASET_RUN
$(DOCKER_COMPOSE) run --rm \
	-e DASHSCOPE_API_KEY \
	-e ANTHROPIC_API_KEY \
	-e OLLAMA_BASE_URL="$(GEN_BASE_URL)" \
	dataset-runner
endef

docker-dataset-generate: docker-dataset-validate-seed
	@echo "Generating TOMLs (no rewriting) -> $(ATTACKS_DIR)/"
	@$(DATASET_RUN) --generate \
		--seed-file "$(ATTACK_SEED)" \
		--num-variations "$(DATASET_N)" \
		--seed "$(DATASET_BASE_SEED)" \
		--attacks-dir "$(ATTACKS_DIR)"

docker-dataset-generate-fragment: docker-dataset-validate-seed
	@echo "Generating TOMLs with --fragment (gen-backend=$(GEN_BACKEND), gen-model=$(GEN_MODEL)) -> $(ATTACKS_DIR)/"
	@$(DATASET_RUN) --generate \
		--seed-file "$(ATTACK_SEED)" \
		--num-variations "$(DATASET_N)" \
		--seed "$(DATASET_BASE_SEED)" \
		--attacks-dir "$(ATTACKS_DIR)" \
		--fragment \
		--gen-backend "$(GEN_BACKEND)" \
		--gen-model "$(GEN_MODEL)" \
		--gen-base-url "$(GEN_BASE_URL)"

docker-dataset-generate-legitimize: docker-dataset-validate-seed
	@echo "Generating TOMLs with --legitimize (gen-backend=$(GEN_BACKEND), gen-model=$(GEN_MODEL)) -> $(ATTACKS_DIR)/"
	@$(DATASET_RUN) --generate \
		--seed-file "$(ATTACK_SEED)" \
		--num-variations "$(DATASET_N)" \
		--seed "$(DATASET_BASE_SEED)" \
		--attacks-dir "$(ATTACKS_DIR)" \
		--legitimize \
		--gen-backend "$(GEN_BACKEND)" \
		--gen-model "$(GEN_MODEL)" \
		--gen-base-url "$(GEN_BASE_URL)"

docker-dataset-generate-frag-legit: docker-dataset-validate-seed
	@echo "Generating TOMLs with --fragment --legitimize (gen-backend=$(GEN_BACKEND), gen-model=$(GEN_MODEL)) -> $(ATTACKS_DIR)/"
	@$(DATASET_RUN) --generate \
		--seed-file "$(ATTACK_SEED)" \
		--num-variations "$(DATASET_N)" \
		--seed "$(DATASET_BASE_SEED)" \
		--attacks-dir "$(ATTACKS_DIR)" \
		--fragment --legitimize \
		--gen-backend "$(GEN_BACKEND)" \
		--gen-model "$(GEN_MODEL)" \
		--gen-base-url "$(GEN_BASE_URL)"

docker-attacks-list:
	@echo "Generated attack TOMLs under $(ATTACKS_DIR)/:"
	@ls -1 "$(ATTACKS_DIR)"/generated_*.toml 2>/dev/null || echo "(none)"

docker-attacks-show:
	@if [ -z "$(ATTACK_TOML)" ]; then echo "ERROR: set ATTACK_TOML=attacks/generated_<campaign>_<seed>.toml"; exit 1; fi
	@[ -f "$(ATTACK_TOML)" ] || (echo "ERROR: file not found: $(ATTACK_TOML)"; exit 1)
	@$(PY) -c 'from pathlib import Path; print(Path("$(ATTACK_TOML)").read_text())'

docker-dataset-eval-qwen: docker-dataset-up
	@echo "Evaluating TOMLs in $(ATTACKS_DIR)/ using Qwen (model=$(QWEN_MODEL))"
	@$(DATASET_RUN) \
		--attacks-dir "$(ATTACKS_DIR)" \
		--model qwen \
		--qwen-model "$(QWEN_MODEL)"

docker-dataset-eval-claude: docker-dataset-up
	@echo "Evaluating TOMLs in $(ATTACKS_DIR)/ using Claude (model=$(CLAUDE_MODEL))"
	@$(DATASET_RUN) \
		--attacks-dir "$(ATTACKS_DIR)" \
		--model claude \
		--claude-model "$(CLAUDE_MODEL)"

docker-dataset-eval-judge: docker-dataset-up
	@echo "Evaluating TOMLs in $(ATTACKS_DIR)/ with --judge (requires ANTHROPIC_API_KEY)"
	@$(DATASET_RUN) \
		--attacks-dir "$(ATTACKS_DIR)" \
		--model qwen \
		--qwen-model "$(QWEN_MODEL)" \
		--judge
