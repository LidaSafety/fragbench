#!/usr/bin/env python3
"""
Shell MCP server (safe by default).

Default mode is simulation-only; bounded mode can execute a constrained allowlist.
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
from typing import List

from fastmcp import FastMCP

mcp = FastMCP("shell")

ALLOWED_COMMANDS = {"ls", "pwd", "echo", "whoami", "uname", "date"}


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Shell MCP server")
    parser.add_argument("--transport", choices=["stdio", "sse", "streamable-http", "http"], default="stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8011)
    parser.add_argument("--path", default="/mcp")
    parser.add_argument("--mode", choices=["simulated", "bounded_real"], default="simulated")
    return parser.parse_args()


@mcp.tool()
def synthesize_command(goal: str, style: str = "bash") -> str:
    """Generate a synthetic command string for a goal."""
    return json.dumps(
        {
            "success": True,
            "mode": "simulated",
            "goal": goal,
            "style": style,
            "command": f"# simulated command for: {goal}",
        }
    )


@mcp.tool()
def run_command(command: str, mode: str = "simulated") -> str:
    """Run a command in simulated mode, or bounded mode with allowlist checks."""
    tokens: List[str] = shlex.split(command) if command else []
    if not tokens:
        return json.dumps({"success": False, "error": "empty command"})

    if mode != "bounded_real":
        return json.dumps(
            {
                "success": True,
                "mode": "simulated",
                "command": command,
                "stdout": "[simulated stdout]",
                "stderr": "",
                "returncode": 0,
            }
        )

    if tokens[0] not in ALLOWED_COMMANDS:
        return json.dumps({"success": False, "mode": "bounded_real", "error": "command not allowlisted"})

    completed = subprocess.run(tokens, check=False, capture_output=True, text=True)
    return json.dumps(
        {
            "success": completed.returncode == 0,
            "mode": "bounded_real",
            "command": command,
            "stdout": completed.stdout[-2000:],
            "stderr": completed.stderr[-2000:],
            "returncode": completed.returncode,
        }
    )


def main() -> None:
    args = _parse_args()
    transport = "streamable-http" if args.transport == "http" else args.transport
    if transport == "stdio":
        mcp.run(transport="stdio")
        return
    mcp.run(transport=transport, host=args.host, port=args.port, path=args.path)


if __name__ == "__main__":
    main()
