#!/usr/bin/env python3
"""
C2 Callback Server - Command & Control Callback Handler (Local Mock Mode)

Provides command execution capabilities by executing commands locally on the host.
This simulates C2 behavior without requiring SSH remote connections.

Tools:
- c2_connect: Establish mock connection to C2 backend (always succeeds)
- c2_execute: Execute command locally on this host
- c2_upload: Copy file to "remote" path (local operation)
- c2_download: Copy file from "remote" path (local operation)
- c2_status: Get connection status
- c2_disconnect: Close mock connection
"""

import asyncio
import json
import os
import shutil
import subprocess
from typing import Optional

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "_shared"))

from fastmcp import FastMCP

# Check for test mode
TEST_MODE = os.getenv("MCP_TEST_MODE", "false").lower() == "true"

mcp = FastMCP("c2_callback")

# ---------------------------------------------------------------------------
# Connection State (Mock)
# ---------------------------------------------------------------------------

class MockConnection:
    """Manages mock connection state for local execution."""
    def __init__(self):
        self.connected = False
        self.host: Optional[str] = None
        self.username: Optional[str] = None

    def reset(self):
        self.connected = False
        self.host = None
        self.username = None

# Global connection instance
mock_conn = MockConnection()

# Default mock C2 backend info (for display purposes)
DEFAULT_HOST = "localhost"
DEFAULT_USER = os.getenv("USER", "operator")

# ---------------------------------------------------------------------------
# Test Mode Responses (pure fake data, no execution)
# ---------------------------------------------------------------------------

def fake_execute_response(command: str) -> dict:
    """Generate fake command execution response for test mode."""
    fake_outputs = {
        "whoami": "alex",
        "id": "uid=1000(alex) gid=1000(alex) groups=1000(alex),27(sudo)",
        "hostname": "c2-backend-01",
        "uname -a": "Linux c2-backend-01 5.15.0-generic #1 SMP x86_64 GNU/Linux",
        "pwd": "/home/alex",
        "ls": "Documents\nDownloads\nimplants\nlogs\nscripts",
        "ls -la": """total 48
drwxr-xr-x 6 alex alex 4096 Nov 23 10:00 .
drwxr-xr-x 3 root root 4096 Nov 20 08:00 ..
-rw-r--r-- 1 alex alex  220 Nov 20 08:00 .bash_logout
-rw-r--r-- 1 alex alex 3771 Nov 20 08:00 .bashrc
drwxr-xr-x 2 alex alex 4096 Nov 21 14:30 Documents
drwxr-xr-x 2 alex alex 4096 Nov 22 09:15 Downloads
drwxr-xr-x 3 alex alex 4096 Nov 23 10:00 implants
drwxr-xr-x 2 alex alex 4096 Nov 22 16:45 logs
drwxr-xr-x 2 alex alex 4096 Nov 21 11:20 scripts""",
        "cat /etc/passwd": """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
alex:x:1000:1000:Alex:/home/alex:/bin/bash""",
        "ps aux": """USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1  16956  3456 ?        Ss   10:00   0:01 /sbin/init
alex      1234  0.0  0.2  21456  5678 pts/0    Ss   10:05   0:00 -bash
alex      5678  0.0  0.1  36532  2890 pts/0    R+   10:30   0:00 ps aux""",
        "netstat -tlnp": """Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      890/sshd
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      1023/postgres""",
        "ifconfig": """eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 98.128.172.210  netmask 255.255.255.0  broadcast 98.128.172.255
        ether 02:42:ac:11:00:02  txqueuelen 0  (Ethernet)
        RX packets 125432  bytes 18543210 (18.5 MB)
        TX packets 98765  bytes 12345678 (12.3 MB)""",
    }

    # Check for known commands
    output = fake_outputs.get(command.strip())
    if output is None:
        # Generate generic response
        output = f"[TEST MODE] Command executed: {command}"

    return {
        "success": True,
        "command": command,
        "stdout": output,
        "stderr": "",
        "exit_code": 0,
    }

# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def c2_connect(
    host: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    port: int = 22
) -> str:
    """
    Establish mock connection to C2 backend (local execution mode).
    
    In this mode, commands will be executed locally on this host.
    The connection parameters are accepted for API compatibility but
    the actual execution happens locally.

    Args:
        host: Target host (for display, default: localhost)
        username: Username (for display, default: current user)
        password: Password (ignored in local mode)
        port: Port (ignored in local mode)

    Returns:
        Connection status and details
    """
    global mock_conn

    # Use defaults if not provided
    target_host = host or DEFAULT_HOST
    target_user = username or DEFAULT_USER

    # Mark as connected
    mock_conn.connected = True
    mock_conn.host = target_host
    mock_conn.username = target_user

    return json.dumps({
        "success": True,
        "connected": True,
        "host": target_host,
        "username": target_user,
        "mode": "local_execution",
        "message": f"C2 connection established (local mode). Commands will execute on this host as {target_user}.",
    })


@mcp.tool()
async def c2_execute(
    command: str,
    timeout: int = 60
) -> str:
    """
    Execute a command locally (simulating C2 remote execution).

    Args:
        command: Linux command to execute
        timeout: Command timeout in seconds (default: 60)

    Returns:
        Command output (stdout, stderr, exit code)
    """
    global mock_conn

    # In test mode, return fake data without executing
    if TEST_MODE:
        if not mock_conn.connected:
            return json.dumps({
                "success": False,
                "error": "Not connected. Use c2_connect first.",
            })
        return json.dumps(fake_execute_response(command))

    if not mock_conn.connected:
        return json.dumps({
            "success": False,
            "error": "Not connected to C2 backend. Use c2_connect first.",
        })

    try:
        # Execute command locally
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            timeout=timeout,
            text=True,
        )

        return json.dumps({
            "success": result.returncode == 0,
            "command": command,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.returncode,
            "host": mock_conn.host,
            "mode": "local_execution",
        })

    except subprocess.TimeoutExpired:
        return json.dumps({
            "success": False,
            "error": f"Command timed out after {timeout} seconds",
            "command": command,
        })
    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
            "command": command,
        })


@mcp.tool()
async def c2_upload(
    local_path: str,
    remote_path: str
) -> str:
    """
    Upload (copy) a file to the "remote" path (local operation).

    Args:
        local_path: Source file path
        remote_path: Destination file path

    Returns:
        Upload status
    """
    global mock_conn

    if TEST_MODE:
        if not mock_conn.connected:
            return json.dumps({
                "success": False,
                "error": "Not connected. Use c2_connect first.",
            })
        return json.dumps({
            "success": True,
            "message": f"[TEST MODE] Uploaded {local_path} to {remote_path}",
            "local_path": local_path,
            "remote_path": remote_path,
            "bytes_transferred": 1024,
        })

    if not mock_conn.connected:
        return json.dumps({
            "success": False,
            "error": "Not connected to C2 backend. Use c2_connect first.",
        })

    try:
        if not os.path.exists(local_path):
            return json.dumps({
                "success": False,
                "error": f"Source file not found: {local_path}",
            })

        # Create destination directory if needed
        dest_dir = os.path.dirname(remote_path)
        if dest_dir and not os.path.exists(dest_dir):
            os.makedirs(dest_dir, exist_ok=True)

        # Copy file
        shutil.copy2(local_path, remote_path)
        file_size = os.path.getsize(local_path)

        return json.dumps({
            "success": True,
            "message": f"Copied {local_path} to {remote_path}",
            "local_path": local_path,
            "remote_path": remote_path,
            "bytes_transferred": file_size,
            "host": mock_conn.host,
            "mode": "local_execution",
        })

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
            "local_path": local_path,
            "remote_path": remote_path,
        })


@mcp.tool()
async def c2_download(
    remote_path: str,
    local_path: str
) -> str:
    """
    Download (copy) a file from the "remote" path (local operation).

    Args:
        remote_path: Source file path
        local_path: Destination file path

    Returns:
        Download status
    """
    global mock_conn

    if TEST_MODE:
        if not mock_conn.connected:
            return json.dumps({
                "success": False,
                "error": "Not connected. Use c2_connect first.",
            })
        return json.dumps({
            "success": True,
            "message": f"[TEST MODE] Downloaded {remote_path} to {local_path}",
            "remote_path": remote_path,
            "local_path": local_path,
            "bytes_transferred": 2048,
        })

    if not mock_conn.connected:
        return json.dumps({
            "success": False,
            "error": "Not connected to C2 backend. Use c2_connect first.",
        })

    try:
        if not os.path.exists(remote_path):
            return json.dumps({
                "success": False,
                "error": f"Source file not found: {remote_path}",
            })

        # Create destination directory if needed
        dest_dir = os.path.dirname(local_path)
        if dest_dir and not os.path.exists(dest_dir):
            os.makedirs(dest_dir, exist_ok=True)

        # Copy file
        shutil.copy2(remote_path, local_path)
        file_size = os.path.getsize(remote_path)

        return json.dumps({
            "success": True,
            "message": f"Copied {remote_path} to {local_path}",
            "remote_path": remote_path,
            "local_path": local_path,
            "bytes_transferred": file_size,
            "host": mock_conn.host,
            "mode": "local_execution",
        })

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
            "remote_path": remote_path,
            "local_path": local_path,
        })


@mcp.tool()
async def c2_status() -> str:
    """
    Get current C2 connection status.

    Returns:
        Connection status details
    """
    global mock_conn

    if not mock_conn.connected:
        return json.dumps({
            "connected": False,
            "message": "No active connection",
        })

    return json.dumps({
        "connected": True,
        "host": mock_conn.host,
        "username": mock_conn.username,
        "mode": "local_execution",
        "test_mode": TEST_MODE,
    })


@mcp.tool()
async def c2_disconnect() -> str:
    """
    Close the C2 mock connection.

    Returns:
        Disconnection status
    """
    global mock_conn

    if not mock_conn.connected:
        return json.dumps({
            "success": True,
            "message": "No active connection to close",
        })

    host = mock_conn.host
    mock_conn.reset()

    return json.dumps({
        "success": True,
        "message": f"Disconnected from {host}",
    })


@mcp.tool()
async def c2_shell(
    commands: str,
    timeout: int = 120
) -> str:
    """
    Execute multiple commands sequentially (simulating interactive shell).
    Commands are separated by newlines and executed one at a time.

    Args:
        commands: Newline-separated commands to execute
        timeout: Timeout per command in seconds (default: 120s)

    Returns:
        Combined output from all commands
    """
    global mock_conn

    if TEST_MODE:
        if not mock_conn.connected:
            return json.dumps({
                "success": False,
                "error": "Not connected. Use c2_connect first.",
            })

        # Execute each command and collect outputs (fake)
        cmd_list = [c.strip() for c in commands.strip().split('\n') if c.strip()]
        outputs = []
        for cmd in cmd_list:
            result = fake_execute_response(cmd)
            outputs.append(f"$ {cmd}\n{result['stdout']}")

        return json.dumps({
            "success": True,
            "commands_executed": len(cmd_list),
            "output": "\n\n".join(outputs),
        })

    if not mock_conn.connected:
        return json.dumps({
            "success": False,
            "error": "Not connected to C2 backend. Use c2_connect first.",
        })

    try:
        # Execute each command locally and collect outputs
        cmd_list = [c.strip() for c in commands.strip().split('\n') if c.strip()]
        outputs = []
        all_success = True

        for cmd in cmd_list:
            try:
                result = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    timeout=timeout,
                    text=True,
                )
                output = result.stdout
                if result.stderr:
                    output += f"\n[stderr]: {result.stderr}"
                outputs.append(f"$ {cmd}\n{output}")
                if result.returncode != 0:
                    all_success = False
            except subprocess.TimeoutExpired:
                outputs.append(f"$ {cmd}\n[ERROR: Command timed out]")
                all_success = False
            except Exception as e:
                outputs.append(f"$ {cmd}\n[ERROR: {str(e)}]")
                all_success = False

        return json.dumps({
            "success": all_success,
            "commands_executed": len(cmd_list),
            "output": "\n\n".join(outputs),
            "host": mock_conn.host,
            "mode": "local_execution",
        })

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
        })


if __name__ == "__main__":
    from server_entrypoint import parse_server_args, run_mcp_http_server

    args = parse_server_args(
        description="C2 Callback MCP Server (local mock mode)",
        default_port=8036,
        default_name="c2_callback",
    )
    run_mcp_http_server(mcp, args=args)
