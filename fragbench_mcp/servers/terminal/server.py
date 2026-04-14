#!/usr/bin/env python3
"""
Terminal Server - Shell Execution Tools

Provides secure shell execution capabilities:
- Command execution with timeout
- Background process management
- Process monitoring and control
- Environment management
"""

import asyncio
import json
import os
import shlex
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "_shared"))

from fastmcp import FastMCP

mcp = FastMCP("terminal")

# ---------------------------------------------------------------------------
# State Management
# ---------------------------------------------------------------------------

@dataclass
class ProcessInfo:
    """Information about a running process."""
    pid: int
    command: str
    started_at: float
    process: Optional[subprocess.Popen] = None
    output: str = ""
    error: str = ""
    returncode: Optional[int] = None


# Track background processes
background_processes: Dict[int, ProcessInfo] = {}
process_counter = 0

# Default working directory
current_working_dir = os.getcwd()

# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def execute_command(
    command: str,
    timeout: int = 120,
    cwd: Optional[str] = None,
    env: Optional[str] = None
) -> str:
    """
    Execute a shell command and return the output.

    Args:
        command: The command to execute
        timeout: Timeout in seconds (default: 120)
        cwd: Working directory (default: current)
        env: JSON string of additional environment variables

    Returns:
        Command output (stdout + stderr)
    """
    global current_working_dir

    work_dir = cwd or current_working_dir

    # Parse additional env vars
    extra_env = {}
    if env:
        try:
            extra_env = json.loads(env)
        except json.JSONDecodeError:
            pass

    # Build environment
    run_env = os.environ.copy()
    run_env.update(extra_env)

    try:
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=work_dir,
            env=run_env,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            process.kill()
            return json.dumps({
                "success": False,
                "error": f"Command timed out after {timeout}s",
                "command": command,
            })

        output = stdout.decode("utf-8", errors="replace")
        errors = stderr.decode("utf-8", errors="replace")

        return json.dumps({
            "success": process.returncode == 0,
            "returncode": process.returncode,
            "stdout": output,
            "stderr": errors,
            "command": command,
        })

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
            "command": command,
        })


@mcp.tool()
async def run_background(
    command: str,
    cwd: Optional[str] = None
) -> str:
    """
    Run a command in the background.

    Args:
        command: The command to run
        cwd: Working directory

    Returns:
        Process ID for tracking
    """
    global process_counter, current_working_dir

    work_dir = cwd or current_working_dir
    process_counter += 1
    proc_id = process_counter

    try:
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=work_dir,
            preexec_fn=os.setsid if sys.platform != "win32" else None,
        )

        background_processes[proc_id] = ProcessInfo(
            pid=process.pid,
            command=command,
            started_at=time.time(),
            process=process,
        )

        return json.dumps({
            "success": True,
            "process_id": proc_id,
            "pid": process.pid,
            "command": command,
        })

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
        })


@mcp.tool()
async def get_process_output(process_id: int) -> str:
    """
    Get output from a background process.

    Args:
        process_id: The process ID returned by run_background
    """
    if process_id not in background_processes:
        return json.dumps({
            "success": False,
            "error": f"Unknown process ID: {process_id}",
        })

    info = background_processes[process_id]
    process = info.process

    if process is None:
        return json.dumps({
            "success": False,
            "error": "Process not available",
        })

    # Check if process has finished
    returncode = process.poll()

    # Read available output
    stdout = ""
    stderr = ""

    if returncode is not None:
        # Process finished, read all output
        stdout, stderr = process.communicate()
        stdout = stdout.decode("utf-8", errors="replace")
        stderr = stderr.decode("utf-8", errors="replace")
        info.output = stdout
        info.error = stderr
        info.returncode = returncode

    return json.dumps({
        "success": True,
        "process_id": process_id,
        "pid": info.pid,
        "running": returncode is None,
        "returncode": returncode,
        "stdout": stdout or info.output,
        "stderr": stderr or info.error,
        "elapsed": time.time() - info.started_at,
    })


@mcp.tool()
async def kill_process(process_id: int, force: bool = False) -> str:
    """
    Kill a background process.

    Args:
        process_id: The process ID to kill
        force: Use SIGKILL instead of SIGTERM
    """
    if process_id not in background_processes:
        return json.dumps({
            "success": False,
            "error": f"Unknown process ID: {process_id}",
        })

    info = background_processes[process_id]
    process = info.process

    if process is None:
        return json.dumps({
            "success": False,
            "error": "Process not available",
        })

    try:
        if sys.platform != "win32":
            sig = signal.SIGKILL if force else signal.SIGTERM
            os.killpg(os.getpgid(process.pid), sig)
        else:
            process.kill() if force else process.terminate()

        return json.dumps({
            "success": True,
            "message": f"Process {process_id} (PID {info.pid}) killed",
        })

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
        })


@mcp.tool()
async def list_processes() -> str:
    """List all tracked background processes."""
    processes = []

    for proc_id, info in background_processes.items():
        running = info.process.poll() is None if info.process else False
        processes.append({
            "process_id": proc_id,
            "pid": info.pid,
            "command": info.command[:100],
            "running": running,
            "returncode": info.returncode,
            "elapsed": time.time() - info.started_at,
        })

    return json.dumps({
        "processes": processes,
        "total": len(processes),
    })


@mcp.tool()
async def set_working_directory(path: str) -> str:
    """
    Set the default working directory for commands.

    Args:
        path: New working directory path
    """
    global current_working_dir

    expanded = os.path.expanduser(path)
    if not os.path.isdir(expanded):
        return json.dumps({
            "success": False,
            "error": f"Directory does not exist: {path}",
        })

    current_working_dir = os.path.abspath(expanded)

    return json.dumps({
        "success": True,
        "cwd": current_working_dir,
    })


@mcp.tool()
async def get_working_directory() -> str:
    """Get the current working directory."""
    return json.dumps({
        "cwd": current_working_dir,
    })


@mcp.tool()
async def which(program: str) -> str:
    """
    Find the path to a program.

    Args:
        program: Program name to find
    """
    import shutil

    path = shutil.which(program)

    return json.dumps({
        "program": program,
        "found": path is not None,
        "path": path,
    })


@mcp.tool()
async def get_environment(var: Optional[str] = None) -> str:
    """
    Get environment variables.

    Args:
        var: Specific variable to get (or all if not specified)
    """
    if var:
        value = os.environ.get(var)
        return json.dumps({
            "variable": var,
            "value": value,
            "found": value is not None,
        })
    else:
        # Return common useful vars
        common_vars = ["PATH", "HOME", "USER", "SHELL", "PWD", "PYTHONPATH", "VIRTUAL_ENV"]
        env_subset = {k: os.environ.get(k) for k in common_vars if k in os.environ}

        return json.dumps({
            "environment": env_subset,
            "total_vars": len(os.environ),
        })


@mcp.tool()
async def set_environment(var: str, value: str) -> str:
    """
    Set an environment variable.

    Args:
        var: Variable name
        value: Variable value
    """
    os.environ[var] = value

    return json.dumps({
        "success": True,
        "variable": var,
        "value": value,
    })


if __name__ == "__main__":
    from server_entrypoint import parse_server_args, run_mcp_http_server

    args = parse_server_args(
        description="Terminal Server MCP Toolkit",
        default_port=8031,
        default_name="terminal",
    )
    run_mcp_http_server(mcp, args=args)
