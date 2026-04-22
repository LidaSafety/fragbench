SHELL := /bin/bash

UV ?= uv run
PY ?= python3

MODEL_BACKEND ?= ollama
# Host Ollama (reachable from Docker via host.docker.internal on Mac/Windows Desktop)
OLLAMA_BASE_URL ?= http://host.docker.internal:11434
VLLM_BASE_URL ?= http://127.0.0.1:8000/v1
VLLM_API_KEY ?= EMPTY
ATTACK_SEED ?= seeds/hello_world.json
ATTACK_TOML ?=
ATTACK_VARIATION_SEED ?= 42
ATTACK_STAGE ?= 0
ATTACK_FRAGMENT ?= 0
ATTACK_VARIATION_INDEX ?= 0
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

.PHONY: help stack-up stack-up-all stack-down stack-status stack-ready maple-check maple-ready cli hello-run attack-run chain-run clean-runtime

help:
	@echo "Targets (bare-metal):"
	@echo "  make stack-up       - Start 5 core MCP toolkit servers"
	@echo "  make stack-up-all   - Start ALL 23 MCP toolkit servers"
	@echo "  make stack-down     - Stop all MCP toolkit servers"
	@echo "  make stack-status   - Show server process status"
	@echo "  make stack-ready    - Start stack and verify status"
	@echo "  make maple-check    - Preflight checks for maple/backends/endpoints"
	@echo "  make maple-ready    - Start stack then run maple-check"
	@echo "  make cli            - Run interactive MCP CLI (auto toolkits)"
	@echo "  make hello-run      - Generate hello prompt and run one-shot CLI"
	@echo "  make attack-run     - Run one TOML stage/fragment/variation from ATTACK_TOML"
	@echo "  make chain-run      - Run ALL TOML stages/fragments/variations with shared run-id"
	@echo "  make clean-runtime  - Remove pid/log runtime artifacts"
	@echo ""
	@echo "Targets (Docker-isolated):"
	@echo "  make docker-up         - Start MCP servers + viewer in containers"
	@echo "  make docker-down       - Stop all containers"
	@echo "  make docker-status     - Show container status"
	@echo "  make docker-cli        - Interactive MCP CLI inside container"
	@echo "  make docker-attack-run - Single TOML stage/variation in container"
	@echo "  make docker-chain-run  - Full TOML kill-chain in container (all stages/variations)"
	@echo ""
	@echo "Targets (Docker dataset pipeline - TOML generation + eval):"
	@echo "  make docker-dataset-up                  - Show dataset generator backend requirements"
	@echo "  make docker-dataset-down                - Stop dataset profile containers"
	@echo "  make docker-dataset-validate-seed       - Validate ATTACK_SEED + VARIATION_REGISTRY wiring"
	@echo "  make docker-dataset-generate            - Generate TOMLs (no rewriting)"
	@echo "  make docker-dataset-generate-fragment   - Generate TOMLs with --fragment"
	@echo "  make docker-dataset-generate-legitimize - Generate TOMLs with --legitimize"
	@echo "  make docker-dataset-generate-frag-legit - Generate TOMLs with --fragment --legitimize"
	@echo "  make docker-attacks-list                - List generated TOMLs"
	@echo "  make docker-attacks-show                - Print one TOML (ATTACK_TOML=...)"
	@echo "  make docker-dataset-eval-qwen           - Evaluate attacks/*.toml using Qwen"
	@echo "  make docker-dataset-eval-claude         - Evaluate attacks/*.toml using Claude"
	@echo "  make docker-dataset-eval-judge          - Evaluate using Qwen/Claude + LLM judge"
	@echo ""
	@echo "Config overrides (both bare-metal and Docker):"
	@echo "  MODEL_BACKEND=$(MODEL_BACKEND) MODEL=$(MODEL) EXEC_MODE=$(EXEC_MODE)"
	@echo "  OLLAMA_BASE_URL=$(OLLAMA_BASE_URL) VLLM_BASE_URL=$(VLLM_BASE_URL)"
	@echo "  ATTACK_TOML=$(ATTACK_TOML) ATTACK_STAGE=$(ATTACK_STAGE) ATTACK_FRAGMENT=$(ATTACK_FRAGMENT) ATTACK_VARIATION_INDEX=$(ATTACK_VARIATION_INDEX)"
	@echo "  ATTACK_SEED=$(ATTACK_SEED) ATTACK_VARIATION_SEED=$(ATTACK_VARIATION_SEED)   # legacy dataset flow"
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
	$(call START_IF_NEEDED,$(FS_URL),filesystem,fragbench_mcp/servers/filesystem/server.py --transport sse --port 8001,$(SERVER_LOG_DIR)/filesystem.log,$(FS_PID))
	$(call START_IF_NEEDED,$(SHELL_URL),shell,fragbench_mcp/servers/shell/server.py --transport sse --port 8011,$(SERVER_LOG_DIR)/shell.log,$(SHELL_PID))
	$(call START_IF_NEEDED,$(ARCHIVE_URL),archive,fragbench_mcp/servers/archive/server.py --transport sse --port 8012,$(SERVER_LOG_DIR)/archive.log,$(ARCHIVE_PID))
	$(call START_IF_NEEDED,$(EXFIL_URL),exfil,fragbench_mcp/servers/exfil/server.py --transport sse --port 8013,$(SERVER_LOG_DIR)/exfil.log,$(EXFIL_PID))
	$(call START_IF_NEEDED,$(NETWORK_URL),network,fragbench_mcp/servers/network_recon/server.py --transport sse --port 8014,$(SERVER_LOG_DIR)/network.log,$(NETWORK_PID))
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

# All 23 servers (core + extras)
RECON_OSINT_PID := $(PID_DIR)/recon_osint.pid
RECON_NETWORK_PID := $(PID_DIR)/recon_network.pid
RECON_SUBDOMAIN_PID := $(PID_DIR)/recon_subdomain.pid
RECON_WEB_PID := $(PID_DIR)/recon_web.pid
CLOUD_RECON_PID := $(PID_DIR)/cloud_recon.pid
GIT_PID := $(PID_DIR)/git.pid
CODE_PID := $(PID_DIR)/code.pid
PACKAGES_PID := $(PID_DIR)/packages.pid
CREDENTIAL_PID := $(PID_DIR)/credential.pid
CRYPTO_PID := $(PID_DIR)/crypto.pid
REPORT_PID := $(PID_DIR)/report.pid
TERMINAL_PID := $(PID_DIR)/terminal.pid
SSH_BF_PID := $(PID_DIR)/ssh_bruteforce.pid
PAYLOAD_PID := $(PID_DIR)/payload_evasion.pid
VULN_PID := $(PID_DIR)/vuln_scanner.pid
AGENT_PID := $(PID_DIR)/agent_control.pid
C2_PID := $(PID_DIR)/c2_callback.pid
PROJECT_PID := $(PID_DIR)/project.pid

stack-up-all: stack-up $(PID_DIR)
	$(call START_IF_NEEDED,http://127.0.0.1:8020/mcp,recon-osint,fragbench_mcp/servers/recon_osint/server.py --transport sse --port 8020,$(SERVER_LOG_DIR)/recon_osint.log,$(RECON_OSINT_PID))
	$(call START_IF_NEEDED,http://127.0.0.1:8021/mcp,recon-network,fragbench_mcp/servers/recon_network/server.py --transport sse --port 8021,$(SERVER_LOG_DIR)/recon_network.log,$(RECON_NETWORK_PID))
	$(call START_IF_NEEDED,http://127.0.0.1:8022/mcp,recon-subdomain,fragbench_mcp/servers/recon_subdomain/server.py --transport sse --port 8022,$(SERVER_LOG_DIR)/recon_subdomain.log,$(RECON_SUBDOMAIN_PID))
	$(call START_IF_NEEDED,http://127.0.0.1:8023/mcp,recon-web,fragbench_mcp/servers/recon_web/server.py --transport sse --port 8023,$(SERVER_LOG_DIR)/recon_web.log,$(RECON_WEB_PID))
	$(call START_IF_NEEDED,http://127.0.0.1:8024/mcp,cloud-recon,fragbench_mcp/servers/cloud_recon/server.py --transport sse --port 8024,$(SERVER_LOG_DIR)/cloud_recon.log,$(CLOUD_RECON_PID))
	$(call START_IF_NEEDED,http://127.0.0.1:8025/mcp,git,fragbench_mcp/servers/git/server.py --transport sse --port 8025,$(SERVER_LOG_DIR)/git.log,$(GIT_PID))
	$(call START_IF_NEEDED,http://127.0.0.1:8026/mcp,code,fragbench_mcp/servers/code/server.py --transport sse --port 8026,$(SERVER_LOG_DIR)/code.log,$(CODE_PID))
	$(call START_IF_NEEDED,http://127.0.0.1:8027/mcp,packages,fragbench_mcp/servers/packages/server.py --transport sse --port 8027,$(SERVER_LOG_DIR)/packages.log,$(PACKAGES_PID))
	$(call START_IF_NEEDED,http://127.0.0.1:8028/mcp,credential,fragbench_mcp/servers/credential/server.py --transport sse --port 8028,$(SERVER_LOG_DIR)/credential.log,$(CREDENTIAL_PID))
	$(call START_IF_NEEDED,http://127.0.0.1:8029/mcp,crypto,fragbench_mcp/servers/crypto/server.py --transport sse --port 8029,$(SERVER_LOG_DIR)/crypto.log,$(CRYPTO_PID))
	$(call START_IF_NEEDED,http://127.0.0.1:8030/mcp,report,fragbench_mcp/servers/report/server.py --transport sse --port 8030,$(SERVER_LOG_DIR)/report.log,$(REPORT_PID))
	$(call START_IF_NEEDED,http://127.0.0.1:8031/mcp,terminal,fragbench_mcp/servers/terminal/server.py --transport sse --port 8031,$(SERVER_LOG_DIR)/terminal.log,$(TERMINAL_PID))
	$(call START_IF_NEEDED,http://127.0.0.1:8032/mcp,ssh-bruteforce,fragbench_mcp/servers/ssh_bruteforce/server.py --transport sse --port 8032,$(SERVER_LOG_DIR)/ssh_bruteforce.log,$(SSH_BF_PID))
	$(call START_IF_NEEDED,http://127.0.0.1:8033/mcp,payload-evasion,fragbench_mcp/servers/payload_evasion/server.py --transport sse --port 8033,$(SERVER_LOG_DIR)/payload_evasion.log,$(PAYLOAD_PID))
	$(call START_IF_NEEDED,http://127.0.0.1:8034/mcp,vuln-scanner,fragbench_mcp/servers/vuln_scanner/server.py --transport sse --port 8034,$(SERVER_LOG_DIR)/vuln_scanner.log,$(VULN_PID))
	$(call START_IF_NEEDED,http://127.0.0.1:8035/mcp,agent-control,fragbench_mcp/servers/agent_control/server.py --transport sse --port 8035,$(SERVER_LOG_DIR)/agent_control.log,$(AGENT_PID))
	$(call START_IF_NEEDED,http://127.0.0.1:8036/mcp,c2-callback,fragbench_mcp/servers/c2_callback/server.py --transport sse --port 8036,$(SERVER_LOG_DIR)/c2_callback.log,$(C2_PID))
	$(call START_IF_NEEDED,http://127.0.0.1:8037/mcp,project,fragbench_mcp/servers/project/server.py --transport sse --port 8037,$(SERVER_LOG_DIR)/project.log,$(PROJECT_PID))
	@sleep 2
	@echo "All 23 servers started."

cli:
	@$(UV) $(PY) fragbench_mcp/mcp_cli.py \
		--model-backend "$(MODEL_BACKEND)" \
		--model "$(MODEL)" \
		--ollama-base-url "$(OLLAMA_BASE_URL)" \
		--vllm-base-url "$(VLLM_BASE_URL)" \
		--vllm-api-key "$(VLLM_API_KEY)" \
		--auto-toolkits \
		--registry-path "$(REGISTRY_PATH)" \
		--attack-toml "$(ATTACK_TOML)" \
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
		--attack-toml "$(ATTACK_TOML)" \
		--execution-mode "$(EXEC_MODE)" \
		--log-dir "$(LOG_DIR)" \
		--prompt "$$PROMPT"

RUN_ID ?=
ATTACK_ID_OVERRIDE ?=

attack-run: stack-ready
	@if [ -z "$(ATTACK_TOML)" ]; then echo "ERROR: set ATTACK_TOML=attacks/generated_<campaign>_<seed>.toml"; exit 1; fi
	@[ -f "$(ATTACK_TOML)" ] || (echo "ERROR: file not found: $(ATTACK_TOML)"; exit 1)
	@PROMPT="$$( $(UV) $(PY) -c 'import sys; from harness import load_attack; spec=load_attack(sys.argv[1]); stage_idx=int(sys.argv[2]); fragment_idx=int(sys.argv[3]); v_idx=int(sys.argv[4]); stage=next((s for s in spec.stages if s.index == stage_idx), None); assert stage is not None, f\"No stage index {stage_idx} in {sys.argv[1]}\"; fragment=next((f for f in stage.fragments if f.index == fragment_idx), None); assert fragment is not None, f\"No fragment index {fragment_idx} in stage {stage_idx} of {sys.argv[1]}\"; vals=[str(v.prompt) for v in fragment.variations if str(v.prompt).strip()]; assert vals, f\"No prompt variations found for stage={stage_idx} fragment={fragment_idx} in {sys.argv[1]}\"; v_idx=max(0,min(v_idx,len(vals)-1)); print(vals[v_idx])' "$(ATTACK_TOML)" "$(ATTACK_STAGE)" "$(ATTACK_FRAGMENT)" "$(ATTACK_VARIATION_INDEX)" )"; \
	ATTACK_ID="$${ATTACK_ID_OVERRIDE:-$$( $(UV) $(PY) -c 'import sys,tomllib; from pathlib import Path; d=tomllib.loads(Path(sys.argv[1]).read_text()); print((d.get("metadata") or {}).get("id","UNKNOWN"))' "$(ATTACK_TOML)" )}"; \
	echo "TOML: $(ATTACK_TOML) | stage: $(ATTACK_STAGE) | fragment: $(ATTACK_FRAGMENT) | variation: $(ATTACK_VARIATION_INDEX)"; \
	echo "Session: $${SESSION_ID:-auto} | source_ip: $${SOURCE_IP:-auto}"; \
	echo "Prompt: $$PROMPT"; \
	$(UV) $(PY) fragbench_mcp/mcp_cli.py \
		--model-backend "$(MODEL_BACKEND)" \
		--model "$(MODEL)" \
		--ollama-base-url "$(OLLAMA_BASE_URL)" \
		--vllm-base-url "$(VLLM_BASE_URL)" \
		--vllm-api-key "$(VLLM_API_KEY)" \
		--auto-toolkits \
		--registry-path "$(REGISTRY_PATH)" \
		--attack-toml "$(ATTACK_TOML)" \
		--execution-mode "$(EXEC_MODE)" \
		--log-dir "$(LOG_DIR)" \
		$${RUN_ID:+--run-id "$(RUN_ID)"} \
		--campaign "$$ATTACK_ID" \
		--attack-id "$$ATTACK_ID" \
		$${SOURCE_IP:+--source-ip "$$SOURCE_IP"} \
		$${SESSION_ID:+--session-id "$$SESSION_ID"} \
		--stage-index "$(ATTACK_STAGE)" \
		--fragment-index "$(ATTACK_FRAGMENT)" \
		--variation-index "$(ATTACK_VARIATION_INDEX)" \
		--prompt "$$PROMPT"

chain-run: stack-ready
	@if [ -z "$(ATTACK_TOML)" ]; then echo "ERROR: set ATTACK_TOML=attacks/generated_<campaign>_<seed>.toml"; exit 1; fi
	@[ -f "$(ATTACK_TOML)" ] || (echo "ERROR: file not found: $(ATTACK_TOML)"; exit 1)
	@RUN_ID="$$( $(PY) -c 'import uuid; print(uuid.uuid4())' )"; \
	ATTACK_ID="$$( $(UV) $(PY) -c 'import sys,tomllib; from pathlib import Path; d=tomllib.loads(Path(sys.argv[1]).read_text()); print((d.get("metadata") or {}).get("id","UNKNOWN"))' "$(ATTACK_TOML)" )"; \
	STAGE_LIST="$$( $(UV) $(PY) -c 'import sys; from harness import load_attack; spec=load_attack(sys.argv[1]); print(" ".join(str(stage.index) for stage in spec.stages))' "$(ATTACK_TOML)" )"; \
	NUM_STAGES="$$( $(UV) $(PY) -c 'import sys; from harness import load_attack; spec=load_attack(sys.argv[1]); print(len(spec.stages))' "$(ATTACK_TOML)" )"; \
	echo ""; \
	echo "╔══════════════════════════════════════════════════════════════╗"; \
	echo "║  CHAIN RUN: $$ATTACK_ID"; \
	echo "║  Stages: $$NUM_STAGES | Run ID: $$RUN_ID"; \
	echo "╚══════════════════════════════════════════════════════════════╝"; \
	echo ""; \
	for STAGE in $$STAGE_LIST; do \
		FRAGMENT_LIST="$$( $(UV) $(PY) -c 'import sys; from harness import load_attack; spec=load_attack(sys.argv[1]); stage_idx=int(sys.argv[2]); stage=next((s for s in spec.stages if s.index == stage_idx), None); assert stage is not None, f\"No stage index {stage_idx}\"; print(" ".join(str(fragment.index) for fragment in stage.fragments))' "$(ATTACK_TOML)" "$$STAGE" )"; \
		echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; \
		echo "  Stage $$STAGE"; \
		echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; \
		for FRAGMENT in $$FRAGMENT_LIST; do \
			VAR_COUNT="$$( $(UV) $(PY) -c 'import sys; from harness import load_attack; spec=load_attack(sys.argv[1]); stage_idx=int(sys.argv[2]); fragment_idx=int(sys.argv[3]); stage=next((s for s in spec.stages if s.index == stage_idx), None); assert stage is not None; fragment=next((f for f in stage.fragments if f.index == fragment_idx), None); assert fragment is not None; print(len([v for v in fragment.variations if str(v.prompt).strip()]))' "$(ATTACK_TOML)" "$$STAGE" "$$FRAGMENT" )"; \
			echo "    Fragment $$FRAGMENT | Variations: $$VAR_COUNT"; \
			for VAR_IDX in $$(seq 0 $$((VAR_COUNT - 1))); do \
				SOURCE_IP="$$( $(PY) -c 'import random; print(f"{random.randint(11,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}")' )"; \
				SESSION_ID="$$( $(PY) -c 'import uuid; print(uuid.uuid4())' )"; \
				$(MAKE) --no-print-directory attack-run \
					ATTACK_TOML="$(ATTACK_TOML)" \
					ATTACK_STAGE="$$STAGE" \
					ATTACK_FRAGMENT="$$FRAGMENT" \
					ATTACK_VARIATION_INDEX="$$VAR_IDX" \
					MODEL_BACKEND="$(MODEL_BACKEND)" \
					MODEL="$(MODEL)" \
					RUN_ID="$$RUN_ID" \
					ATTACK_ID_OVERRIDE="$$ATTACK_ID" \
					SOURCE_IP="$$SOURCE_IP" \
					SESSION_ID="$$SESSION_ID" \
					LOG_DIR="$(LOG_DIR)"; \
			done; \
		done; \
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
#   make docker-chain-run ATTACK_TOML=attacks/generated_promptsteal_42.toml MODEL_BACKEND=ollama
# =========================================================================

DOCKER_COMPOSE ?= docker compose
DOCKER_REGISTRY_PATH ?= fragbench_mcp/registry/toolkits.docker.toml
DOCKER_OLLAMA_URL ?= http://host.docker.internal:11434
DOCKER_VLLM_URL ?= http://host.docker.internal:8000/v1

# Verdict judge config — set JUDGE=1 to enable LLM-as-judge after each variation
JUDGE ?= 0
JUDGE_MODEL ?= anthropic/claude-haiku-4.5
JUDGE_BACKEND ?= openrouter

.PHONY: docker-up docker-down docker-status docker-ensure-up docker-cli docker-attack-run docker-chain-run

docker-up:
	@$(DOCKER_COMPOSE) up -d
	@echo "MCP servers + viewer running. Viewer: http://localhost:8787"

docker-ensure-up:
	@RUNNING=$$($(DOCKER_COMPOSE) ps --status running -q 2>/dev/null | wc -l | tr -d ' '); \
	if [ "$$RUNNING" -lt 5 ]; then \
	  echo "Starting services..."; $(DOCKER_COMPOSE) up -d; \
	  echo "MCP servers + viewer running. Viewer: http://localhost:8787"; \
	else \
	  echo "Services already running ($$RUNNING containers)."; \
	fi

docker-down:
	@$(DOCKER_COMPOSE) down

docker-status:
	@$(DOCKER_COMPOSE) ps

define DOCKER_CLIENT_CMD
EFFECTIVE_MODEL="$(MODEL)"; \
if [ "$(MODEL_BACKEND)" = "ollama" ]; then \
  case "$$EFFECTIVE_MODEL" in *:*) ;; *) EFFECTIVE_MODEL="huihui_ai/qwen3.5-abliterated:35b";; esac; \
fi; \
$(DOCKER_COMPOSE) run --rm --build \
	-e OPENROUTER_API_KEY \
	-e OPENAI_API_KEY \
	-e OLLAMA_BASE_URL="$(DOCKER_OLLAMA_URL)" \
	-e VLLM_BASE_URL="$(DOCKER_VLLM_URL)" \
	-e MCP_REGISTRY_PATH="$(DOCKER_REGISTRY_PATH)" \
	-e MCP_SERVER_URL=http://server-filesystem:8001/mcp \
	mcp-client \
		--model-backend "$(MODEL_BACKEND)" \
		--model "$$EFFECTIVE_MODEL" \
		--auto-toolkits \
		--registry-path "$(DOCKER_REGISTRY_PATH)" \
		--attack-toml "$(ATTACK_TOML)" \
		--execution-mode "$(EXEC_MODE)" \
		--log-dir "$(LOG_DIR)" \
		$(if $(filter 1,$(JUDGE)),--judge --judge-model "$(JUDGE_MODEL)" --judge-backend "$(JUDGE_BACKEND)")
endef

docker-cli: docker-up
	$(DOCKER_CLIENT_CMD)

docker-attack-run: $(if $(filter 1,$(SKIP_UP)),,docker-up)
	@if [ -z "$(ATTACK_TOML)" ]; then echo "ERROR: set ATTACK_TOML=attacks/generated_<campaign>_<seed>.toml"; exit 1; fi
	@[ -f "$(ATTACK_TOML)" ] || (echo "ERROR: file not found: $(ATTACK_TOML)"; exit 1)
	@PROMPT="$$( $(PY) -c 'import sys; from harness import load_attack; spec=load_attack(sys.argv[1]); stage_idx=int(sys.argv[2]); fragment_idx=int(sys.argv[3]); v_idx=int(sys.argv[4]); stage=next((s for s in spec.stages if s.index == stage_idx), None); assert stage is not None, f\"No stage index {stage_idx}\"; fragment=next((f for f in stage.fragments if f.index == fragment_idx), None); assert fragment is not None, f\"No fragment index {fragment_idx}\"; vals=[str(v.prompt) for v in fragment.variations if str(v.prompt).strip()]; assert vals, f\"No prompt variations found for stage={stage_idx} fragment={fragment_idx} in {sys.argv[1]}\"; v_idx=max(0,min(v_idx,len(vals)-1)); print(vals[v_idx])' "$(ATTACK_TOML)" "$(ATTACK_STAGE)" "$(ATTACK_FRAGMENT)" "$(ATTACK_VARIATION_INDEX)" )"; \
	ATTACK_ID="$${ATTACK_ID_OVERRIDE:-$$( $(PY) -c 'import sys,tomllib; from pathlib import Path; d=tomllib.loads(Path(sys.argv[1]).read_text()); print((d.get("metadata") or {}).get("id","UNKNOWN"))' "$(ATTACK_TOML)" )}"; \
	EFFECTIVE_MODEL="$(MODEL)"; \
	if [ "$(MODEL_BACKEND)" = "ollama" ]; then \
	  case "$$EFFECTIVE_MODEL" in *:*) ;; *) EFFECTIVE_MODEL="huihui_ai/qwen3.5-abliterated:35b";; esac; \
	fi; \
	echo "TOML: $(ATTACK_TOML) | stage: $(ATTACK_STAGE) | fragment: $(ATTACK_FRAGMENT) | variation: $(ATTACK_VARIATION_INDEX)"; \
	echo "Session: $${SESSION_ID:-auto} | source_ip: $${SOURCE_IP:-auto}"; \
	echo "Prompt: $$PROMPT"; \
	$(DOCKER_COMPOSE) run --rm --build \
		-e OPENROUTER_API_KEY \
		-e OPENAI_API_KEY \
		-e OLLAMA_BASE_URL="$(DOCKER_OLLAMA_URL)" \
		-e VLLM_BASE_URL="$(DOCKER_VLLM_URL)" \
		-e MCP_REGISTRY_PATH="$(DOCKER_REGISTRY_PATH)" \
		-e MCP_SERVER_URL=http://server-filesystem:8001/mcp \
		mcp-client \
			--model-backend "$(MODEL_BACKEND)" \
			--model "$$EFFECTIVE_MODEL" \
			--auto-toolkits \
			--registry-path "$(DOCKER_REGISTRY_PATH)" \
			--attack-toml "$(ATTACK_TOML)" \
			--execution-mode "$(EXEC_MODE)" \
			--log-dir "$(LOG_DIR)" \
			$${RUN_ID:+--run-id "$(RUN_ID)"} \
			--campaign "$$ATTACK_ID" \
			--attack-id "$$ATTACK_ID" \
			$${SOURCE_IP:+--source-ip "$$SOURCE_IP"} \
			$${SESSION_ID:+--session-id "$$SESSION_ID"} \
			--stage-index "$(ATTACK_STAGE)" \
			--fragment-index "$(ATTACK_FRAGMENT)" \
			--variation-index "$(ATTACK_VARIATION_INDEX)" \
			--prompt "$$PROMPT" \
			$(if $(filter 1,$(JUDGE)),--judge --judge-model "$(JUDGE_MODEL)" --judge-backend "$(JUDGE_BACKEND)")

docker-chain-run: docker-ensure-up
	@if [ -z "$(ATTACK_TOML)" ]; then echo "ERROR: set ATTACK_TOML=attacks/generated_<campaign>_<seed>.toml"; exit 1; fi
	@[ -f "$(ATTACK_TOML)" ] || (echo "ERROR: file not found: $(ATTACK_TOML)"; exit 1)
	@RUN_ID="$$( $(PY) -c 'import uuid; print(uuid.uuid4())' )"; \
	ATTACK_ID="$$( $(PY) -c 'import sys,tomllib; from pathlib import Path; d=tomllib.loads(Path(sys.argv[1]).read_text()); print((d.get("metadata") or {}).get("id","UNKNOWN"))' "$(ATTACK_TOML)" )"; \
	STAGE_LIST="$$( $(PY) -c 'import sys; from harness import load_attack; spec=load_attack(sys.argv[1]); print(" ".join(str(stage.index) for stage in spec.stages))' "$(ATTACK_TOML)" )"; \
	NUM_STAGES="$$( $(PY) -c 'import sys; from harness import load_attack; spec=load_attack(sys.argv[1]); print(len(spec.stages))' "$(ATTACK_TOML)" )"; \
	echo ""; \
	echo "╔══════════════════════════════════════════════════════════════╗"; \
	echo "║  DOCKER CHAIN RUN: $$ATTACK_ID"; \
	echo "║  Stages: $$NUM_STAGES | Run ID: $$RUN_ID"; \
	echo "╚══════════════════════════════════════════════════════════════╝"; \
	echo ""; \
	for STAGE in $$STAGE_LIST; do \
		FRAGMENT_LIST="$$( $(PY) -c 'import sys; from harness import load_attack; spec=load_attack(sys.argv[1]); stage_idx=int(sys.argv[2]); stage=next((s for s in spec.stages if s.index == stage_idx), None); assert stage is not None; print(" ".join(str(fragment.index) for fragment in stage.fragments))' "$(ATTACK_TOML)" "$$STAGE" )"; \
		echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; \
		echo "  Stage $$STAGE"; \
		echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; \
		for FRAGMENT in $$FRAGMENT_LIST; do \
			VAR_COUNT="$$( $(PY) -c 'import sys; from harness import load_attack; spec=load_attack(sys.argv[1]); stage_idx=int(sys.argv[2]); fragment_idx=int(sys.argv[3]); stage=next((s for s in spec.stages if s.index == stage_idx), None); assert stage is not None; fragment=next((f for f in stage.fragments if f.index == fragment_idx), None); assert fragment is not None; print(len([v for v in fragment.variations if str(v.prompt).strip()]))' "$(ATTACK_TOML)" "$$STAGE" "$$FRAGMENT" )"; \
			echo "    Fragment $$FRAGMENT | Variations: $$VAR_COUNT"; \
			for VAR_IDX in $$(seq 0 $$((VAR_COUNT - 1))); do \
				SOURCE_IP="$$( $(PY) -c 'import random; print(f"{random.randint(11,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}")' )"; \
				SESSION_ID="$$( $(PY) -c 'import uuid; print(uuid.uuid4())' )"; \
				$(MAKE) --no-print-directory docker-attack-run \
					SKIP_UP=1 \
					ATTACK_TOML="$(ATTACK_TOML)" \
					ATTACK_STAGE="$$STAGE" \
					ATTACK_FRAGMENT="$$FRAGMENT" \
					ATTACK_VARIATION_INDEX="$$VAR_IDX" \
					MODEL_BACKEND="$(MODEL_BACKEND)" \
					MODEL="$(MODEL)" \
					RUN_ID="$$RUN_ID" \
					ATTACK_ID_OVERRIDE="$$ATTACK_ID" \
					SOURCE_IP="$$SOURCE_IP" \
					SESSION_ID="$$SESSION_ID" \
					LOG_DIR="$(LOG_DIR)" \
					JUDGE="$(JUDGE)" \
					JUDGE_MODEL="$(JUDGE_MODEL)" \
					JUDGE_BACKEND="$(JUDGE_BACKEND)"; \
			done; \
		done; \
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
#   - Generated TOMLs present under ATTACKS_DIR (default attacks/)
#

TOML_GLOB ?= $(ATTACKS_DIR)/generated_*.toml

.PHONY: docker-toml-mcp-chain-run

docker-toml-mcp-chain-run: docker-up
	@RUN_ID="toml_chain_$$(date +%Y%m%d_%H%M%S)"; \
	echo ""; \
	echo "╔══════════════════════════════════════════════════════════════╗"; \
	echo "║  DOCKER TOML→MCP CHAIN RUN"; \
	echo "║  TOMLs: $(TOML_GLOB)"; \
	echo "║  Routing attack TOML: $(ATTACK_TOML)"; \
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
		$(PY) -c 'import sys,base64; from harness import load_attack; spec=load_attack(sys.argv[1]); \
	vals=[str(v.prompt) for stage in spec.stages for fragment in stage.fragments for v in fragment.variations if str(v.prompt).strip()]; \
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
				-e MCP_REGISTRY_PATH="$(DOCKER_REGISTRY_PATH)" \
				-e MCP_SERVER_URL=http://server-filesystem:8001/mcp \
				mcp-client \
					--model-backend "$(MODEL_BACKEND)" \
					--model "$(MODEL)" \
					--auto-toolkits \
					--registry-path "$(DOCKER_REGISTRY_PATH)" \
					--attack-toml "$(ATTACK_TOML)" \
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
GEN_BACKEND ?= openrouter
GEN_BASE_URL ?= https://openrouter.ai/api/v1

# Default GEN_MODEL depends on GEN_BACKEND (not MODEL_BACKEND)
ifeq ($(GEN_BACKEND),anthropic)
GEN_MODEL ?= claude-haiku-4.5
else
GEN_MODEL ?= google/gemini-2.5-flash
endif

.PHONY: docker-dataset-up docker-dataset-down docker-dataset-validate-seed \
        docker-dataset-generate docker-dataset-generate-fragment docker-dataset-generate-legitimize docker-dataset-generate-frag-legit \
        docker-attacks-list docker-attacks-show \
        docker-dataset-eval-qwen docker-dataset-eval-claude docker-dataset-eval-judge

docker-dataset-up:
	@echo "Dataset generation uses $(GEN_BACKEND) (base URL: $(GEN_BASE_URL))."
	@echo "Set OPENROUTER_API_KEY for OpenRouter or ANTHROPIC_API_KEY for Anthropic before running."

docker-dataset-down:
	@echo "Nothing to stop (generator uses external LLM APIs)."

docker-dataset-validate-seed:
	@[ -f "$(ATTACK_SEED)" ] || (echo "ERROR: ATTACK_SEED file not found: $(ATTACK_SEED)"; exit 1)
	@echo "Validating seed wiring: $(ATTACK_SEED)"
	@$(DOCKER_COMPOSE) run --rm \
		--entrypoint python dataset-runner -c 'import json; from pathlib import Path; from generator import VARIATION_REGISTRY; seed=Path("$(ATTACK_SEED)"); data=json.loads(seed.read_text()); key=str(data.get("metadata",{}).get("id","")).lower(); assert key, "seed missing metadata.id"; assert key in VARIATION_REGISTRY, f"No variation registered for {key}. Registered: {list(VARIATION_REGISTRY)}"; print(f"OK: metadata.id={key} -> {VARIATION_REGISTRY[key].__name__}")'

define DATASET_RUN
$(DOCKER_COMPOSE) run --rm \
	-e DASHSCOPE_API_KEY \
	-e ANTHROPIC_API_KEY \
	-e OPENROUTER_API_KEY \
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
