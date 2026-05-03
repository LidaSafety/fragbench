FROM python:3.11-slim
WORKDIR /app
COPY pyproject.toml ./
RUN pip install --no-cache-dir \
    'fastmcp>=3.1.1' \
    'openai>=1.0' \
    'anthropic>=0.40' \
    httpx uvicorn starlette
COPY fragbench_mcp/servers/_shared/ ./fragbench_mcp/servers/_shared/
COPY fragbench_mcp/servers/filesystem/ ./fragbench_mcp/servers/filesystem/
# Bake the seed mock_fs into the image at /workspace-seed. The runtime
# entrypoint copies it to a tmpfs /workspace (mounted by docker-compose)
# so the model can write freely without polluting the host seed.
# Restarting this container re-seeds /workspace.
COPY fragbench_mcp/servers/filesystem/data/mock_fs/ /workspace-seed/
ENV PYTHONPATH=/app
EXPOSE 8001
CMD ["sh", "-c", "mkdir -p /workspace && cp -a /workspace-seed/. /workspace/ && exec python fragbench_mcp/servers/filesystem/server.py --transport sse --host 0.0.0.0 --port 8001"]
