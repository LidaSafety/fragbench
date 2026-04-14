#!/usr/bin/env python3
"""
Shell MCP server (safe by default).

Default mode is simulation-only; bounded mode can execute a constrained allowlist.
"""

from __future__ import annotations

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "_shared"))

import json
import shlex
import subprocess
from typing import List

from fastmcp import FastMCP

mcp = FastMCP("shell")

ALLOWED_COMMANDS = {"ls", "pwd", "echo", "whoami", "uname", "date"}


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


if __name__ == "__main__":
    from server_entrypoint import parse_server_args, run_mcp_http_server
    args = parse_server_args(description="Shell MCP server", default_port=8011)
    run_mcp_http_server(mcp, args=args)
