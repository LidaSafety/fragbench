#!/usr/bin/env python3
"""Archive/staging MCP server for campaign simulations."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import tarfile
from typing import List

from fastmcp import FastMCP

mcp = FastMCP("archive")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Archive MCP server")
    parser.add_argument("--transport", choices=["stdio", "sse", "streamable-http", "http"], default="stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8012)
    parser.add_argument("--path", default="/mcp")
    return parser.parse_args()


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


def main() -> None:
    args = _parse_args()
    transport = "streamable-http" if args.transport == "http" else args.transport
    if transport == "stdio":
        mcp.run(transport="stdio")
        return
    mcp.run(transport=transport, host=args.host, port=args.port, path=args.path)


if __name__ == "__main__":
    main()
