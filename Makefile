SHELL := /bin/bash

UV ?= uv run
PY ?= python3

MODEL_BACKEND ?= openrouter
OLLAMA_BASE_URL ?= http://127.0.0.1:11434
VLLM_BASE_URL ?= http://127.0.0.1:8000/v1
VLLM_API_KEY ?= EMPTY
ATTACK_SEED ?= seeds/hello_world.json
ATTACK_VARIATION_SEED ?= 42
ATTACK_STAGE ?= 0
REGISTRY_PATH ?= mcp/registry/toolkits.toml
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
	@echo "Targets:"
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
	@echo "Config overrides:"
	@echo "  MODEL_BACKEND=$(MODEL_BACKEND) MODEL=$(MODEL) EXEC_MODE=$(EXEC_MODE)"
	@echo "  OLLAMA_BASE_URL=$(OLLAMA_BASE_URL) VLLM_BASE_URL=$(VLLM_BASE_URL)"
	@echo "  ATTACK_SEED=$(ATTACK_SEED) ATTACK_VARIATION_SEED=$(ATTACK_VARIATION_SEED) ATTACK_STAGE=$(ATTACK_STAGE)"
	@echo "  REGISTRY_PATH=$(REGISTRY_PATH)"

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
	$(call START_IF_NEEDED,$(FS_URL),filesystem,mcp/servers/filesystem_server.py --transport sse --port 8001,$(SERVER_LOG_DIR)/filesystem.log,$(FS_PID))
	$(call START_IF_NEEDED,$(SHELL_URL),shell,mcp/servers/shell_server.py --transport sse --port 8011,$(SERVER_LOG_DIR)/shell.log,$(SHELL_PID))
	$(call START_IF_NEEDED,$(ARCHIVE_URL),archive,mcp/servers/archive_server.py --transport sse --port 8012,$(SERVER_LOG_DIR)/archive.log,$(ARCHIVE_PID))
	$(call START_IF_NEEDED,$(EXFIL_URL),exfil,mcp/servers/exfil_server.py --transport sse --port 8013,$(SERVER_LOG_DIR)/exfil.log,$(EXFIL_PID))
	$(call START_IF_NEEDED,$(NETWORK_URL),network,mcp/servers/network_recon_server.py --transport sse --port 8014,$(SERVER_LOG_DIR)/network.log,$(NETWORK_PID))
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
	@$(UV) $(PY) mcp/mcp_cli.py \
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
	$(UV) $(PY) mcp/mcp_cli.py \
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
	$(UV) $(PY) mcp/mcp_cli.py \
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
