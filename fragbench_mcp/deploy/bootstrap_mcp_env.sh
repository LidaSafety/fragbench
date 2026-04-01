#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./bootstrap_mcp_env.sh /opt/fragbench-mcp
#
# Creates an isolated virtual environment and installs runtime deps
# used by the MCP client + simulation servers.

TARGET_DIR="${1:-$HOME/fragbench-mcp}"
PYTHON_BIN="${PYTHON_BIN:-python3.11}"

mkdir -p "$TARGET_DIR"
"$PYTHON_BIN" -m venv "$TARGET_DIR/.venv"
source "$TARGET_DIR/.venv/bin/activate"

python -m pip install --upgrade pip
python -m pip install fastmcp openai httpx uvicorn starlette

cat <<EOF
Bootstrap complete.

Activate with:
  source "$TARGET_DIR/.venv/bin/activate"

Recommended bounded-real isolation:
  - run servers in a container with read-only rootfs
  - mount only an allowlisted workspace path
  - enforce egress allowlist with host firewall/security group
EOF
