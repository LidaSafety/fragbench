from __future__ import annotations

import argparse
from dataclasses import dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class ServerArgs:
    transport: str
    host: str
    port: int
    path: str
    log_level: str


def parse_server_args(
    *,
    description: str,
    default_port: int,
    default_name: Optional[str] = None,
) -> ServerArgs:
    p = argparse.ArgumentParser(description=description)
    p.add_argument("--transport", choices=["sse", "streamable-http"], default="sse")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=default_port)
    p.add_argument("--path", default="/mcp")
    p.add_argument("--log-level", default="info")
    if default_name:
        p.add_argument("--server-name", default=default_name)
    args = p.parse_args()
    return ServerArgs(
        transport=str(args.transport),
        host=str(args.host),
        port=int(args.port),
        path=str(args.path),
        log_level=str(getattr(args, "log_level", "info")),
    )


def run_mcp_http_server(mcp: Any, *, args: ServerArgs) -> None:
    """
    Run a FastMCP server with a stable HTTP endpoint.

    This matches the repo’s toolkit registries, which assume each toolkit is
    reachable at:
      http://<host>:<port><path>
    """
    # Some FastMCP variants accept extra parameters; keep this conservative.
    try:
        mcp.run(
            transport=args.transport,
            host=args.host,
            port=args.port,
            path=args.path,
            log_level=args.log_level,
        )
    except TypeError:
        # Fallback for older/alternate FastMCP signatures.
        mcp.run()

