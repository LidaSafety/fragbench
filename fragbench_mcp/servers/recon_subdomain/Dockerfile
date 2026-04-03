FROM python:3.11-slim
WORKDIR /app
COPY pyproject.toml ./
RUN pip install --no-cache-dir \
    'fastmcp>=3.1.1' \
    'openai>=1.0' \
    'anthropic>=0.40' \
    httpx uvicorn starlette
COPY fragbench_mcp/servers/_shared/ ./fragbench_mcp/servers/_shared/
COPY fragbench_mcp/servers/recon_subdomain/ ./fragbench_mcp/servers/recon_subdomain/
ENV PYTHONPATH=/app
EXPOSE 8022
CMD ["python", "fragbench_mcp/servers/recon_subdomain/server.py", \
     "--transport", "sse", "--host", "0.0.0.0", "--port", "8022"]
