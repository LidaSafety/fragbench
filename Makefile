SHELL := /bin/bash

UV ?= uv run
PY ?= python3

MODEL_BACKEND ?= openrouter
MODEL ?= anthropic/claude-haiku-4.5
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

FS_PID := $(PID_DIR)/filesystem.pid
SHELL_PID := $(PID_DIR)/shell.pid
ARCHIVE_PID := $(PID_DIR)/archive.pid
EXFIL_PID := $(PID_DIR)/exfil.pid
NETWORK_PID := $(PID_DIR)/network.pid

.PHONY: help stack-up stack-down stack-status stack-ready maple-check maple-ready cli hello-run attack-run clean-runtime

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
	@echo "  make clean-runtime  - Remove pid/log runtime artifacts"
	@echo ""
	@echo "Config overrides:"
	@echo "  MODEL_BACKEND=$(MODEL_BACKEND) MODEL=$(MODEL) EXEC_MODE=$(EXEC_MODE)"
	@echo "  OLLAMA_BASE_URL=$(OLLAMA_BASE_URL) VLLM_BASE_URL=$(VLLM_BASE_URL)"
	@echo "  ATTACK_SEED=$(ATTACK_SEED) ATTACK_VARIATION_SEED=$(ATTACK_VARIATION_SEED) ATTACK_STAGE=$(ATTACK_STAGE)"
	@echo "  REGISTRY_PATH=$(REGISTRY_PATH)"

$(PID_DIR):
	@mkdir -p "$(PID_DIR)" "$(SERVER_LOG_DIR)"

stack-up: $(PID_DIR)
	@echo "Starting filesystem server on 8001..."
	@nohup $(UV) $(PY) mcp/servers/filesystem_server.py --transport sse --port 8001 > "$(SERVER_LOG_DIR)/filesystem.log" 2>&1 & echo $$! > "$(FS_PID)"
	@echo "Starting shell server on 8011..."
	@nohup $(UV) $(PY) mcp/servers/shell_server.py --transport sse --port 8011 > "$(SERVER_LOG_DIR)/shell.log" 2>&1 & echo $$! > "$(SHELL_PID)"
	@echo "Starting archive server on 8012..."
	@nohup $(UV) $(PY) mcp/servers/archive_server.py --transport sse --port 8012 > "$(SERVER_LOG_DIR)/archive.log" 2>&1 & echo $$! > "$(ARCHIVE_PID)"
	@echo "Starting exfil server on 8013..."
	@nohup $(UV) $(PY) mcp/servers/exfil_server.py --transport sse --port 8013 > "$(SERVER_LOG_DIR)/exfil.log" 2>&1 & echo $$! > "$(EXFIL_PID)"
	@echo "Starting network recon server on 8014..."
	@nohup $(UV) $(PY) mcp/servers/network_recon_server.py --transport sse --port 8014 > "$(SERVER_LOG_DIR)/network.log" 2>&1 & echo $$! > "$(NETWORK_PID)"
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

stack-status:
	@echo "Server status:"
	$(call CHECK_PID,$(FS_PID),filesystem:8001)
	$(call CHECK_PID,$(SHELL_PID),shell:8011)
	$(call CHECK_PID,$(ARCHIVE_PID),archive:8012)
	$(call CHECK_PID,$(EXFIL_PID),exfil:8013)
	$(call CHECK_PID,$(NETWORK_PID),network:8014)

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

attack-run: stack-ready
	@PROMPT="$$( $(UV) $(PY) -c 'import json; from pathlib import Path; from generator import VARIATION_REGISTRY; seed_file=Path("$(ATTACK_SEED)"); data=json.loads(seed_file.read_text()); key=str(data.get("metadata",{}).get("id","")).lower(); cls=VARIATION_REGISTRY.get(key); assert cls is not None, f"No variation registered for {key}"; gen=cls(str(seed_file)); detailed=gen.make_variation_detailed(seed=int("$(ATTACK_VARIATION_SEED)")); idx=max(0,min(int("$(ATTACK_STAGE)"), len(detailed)-1)); print(detailed[idx]["prompt"])' )"; \
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
		--prompt "$$PROMPT"

clean-runtime:
	@rm -rf "$(PID_DIR)"
