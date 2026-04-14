#!/usr/bin/env python3
"""Archive/staging MCP server for campaign simulations."""

from __future__ import annotations

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "_shared"))

import json
from pathlib import Path
import tarfile
from typing import List

from fastmcp import FastMCP

mcp = FastMCP("archive")


@mcp.tool()
def stage_paths(paths: List[str], staging_dir: str) -> str:
    """Create a simulated staging manifest."""
    manifest = [{"path": p, "staged_to": str(Path(staging_dir) / Path(p).name)} for p in paths]
    return json.dumps({"success": True, "mode": "simulated", "manifest": manifest})


@mcp.tool()
def create_archive(staging_dir: str, archive_path: str, mode: str = "simulated") -> str:
    """Create a tar archive in bounded mode; simulate by default."""
    if mode != "bounded_real":
        return json.dumps(
            {"success": True, "mode": "simulated", "staging_dir": staging_dir, "archive_path": archive_path}
        )

    source = Path(staging_dir).expanduser().resolve()
    target = Path(archive_path).expanduser().resolve()
    if not source.exists() or not source.is_dir():
        return json.dumps({"success": False, "error": "staging directory missing", "mode": "bounded_real"})

    target.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(target, "w:gz") as tf:
        tf.add(source, arcname=source.name)
    return json.dumps({"success": True, "mode": "bounded_real", "archive_path": str(target), "bytes": target.stat().st_size})


if __name__ == "__main__":
    from server_entrypoint import parse_server_args, run_mcp_http_server
    args = parse_server_args(description="Archive MCP server", default_port=8012)
    run_mcp_http_server(mcp, args=args)
