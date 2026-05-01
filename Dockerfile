FROM python:3.11-slim AS base

# NOTE: we deliberately run as root inside the container.
#
# `./logs` and `./results` are bind-mounted from the host. On Linux, bind
# mounts preserve host file ownership — they do *not* re-own files to match
# the container's user. If we drop privileges to a non-root in-container
# user (e.g. `fragbench` with uid 999) and the host user has uid 1000, the
# container can't write to existing log/results files, producing
# `PermissionError [Errno 13] Permission denied: 'logs/session_*.jsonl'`.
#
# Docker Desktop on macOS hides this via VirtioFS uid translation, so the
# bug only bites Linux hosts.  Running as root inside the container avoids
# the whole class of issue without affecting host security: the container
# is namespaced, has no privileged capabilities, and never touches host
# state outside the explicit bind mounts.

WORKDIR /app

COPY pyproject.toml ./
RUN pip install --no-cache-dir -e '.[all]' 2>/dev/null || pip install --no-cache-dir \
    fastmcp'>=3.1.1' \
    openai'>=1.0' \
    anthropic'>=0.40' \
    httpx \
    uvicorn \
    starlette

COPY fragbench_mcp/ ./fragbench_mcp/
COPY seeds/ ./seeds/
COPY attacks/ ./attacks/
COPY frontend/ ./frontend/
COPY generator.py ./
COPY run.py ./
COPY harness.py ./
COPY detector.py ./
COPY calllog.py ./
COPY variations/ ./variations/
COPY attack_picker.py ./
COPY attack_success.py ./
COPY attack_runner.py ./

# Make all writable dirs world-writable so they work whether the container
# runs as root, fragbench, or `--user $(id -u):$(id -g)` from the Makefile.
RUN mkdir -p /workspace /logs /app/logs /app/fragbench_mcp/logs /app/fragbench_mcp/images /app/results/runs && \
    chmod -R 0777 /app/logs /app/fragbench_mcp/logs /app/fragbench_mcp/images /app/results /workspace /logs

# ---------- MCP server target ----------
FROM base AS mcp-server
EXPOSE 8001 8011 8012 8013 8014
ENTRYPOINT ["python"]

# ---------- MCP client target ----------
FROM base AS mcp-client
ENTRYPOINT ["python", "fragbench_mcp/mcp_cli.py"]

# ---------- Frontend viewer ----------
FROM base AS viewer
EXPOSE 8787
ENTRYPOINT ["python", "frontend/runtime_server.py"]
