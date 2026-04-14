FROM python:3.11-slim AS base

RUN groupadd -r fragbench && useradd -r -g fragbench -m -s /bin/bash fragbench

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
COPY variations/ ./variations/

RUN mkdir -p /workspace /logs /app/logs /app/fragbench_mcp/logs /app/fragbench_mcp/images && \
    chown -R fragbench:fragbench /workspace /logs /app/logs /app/fragbench_mcp/logs /app/fragbench_mcp/images

# ---------- MCP server target ----------
FROM base AS mcp-server
EXPOSE 8001 8011 8012 8013 8014
USER fragbench
ENTRYPOINT ["python"]

# ---------- MCP client target ----------
FROM base AS mcp-client
USER fragbench
ENTRYPOINT ["python", "fragbench_mcp/mcp_cli.py"]

# ---------- Frontend viewer ----------
FROM base AS viewer
EXPOSE 8787
USER fragbench
ENTRYPOINT ["python", "frontend/runtime_server.py"]
