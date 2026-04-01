#!/usr/bin/env python3
"""
Package Server - Package Management Tools

Provides package management for multiple ecosystems:
- uv (fast Python package manager)
- pip (standard Python)
- npm/pnpm/yarn (Node.js)
- Virtual environment management
"""

import asyncio
import json
import os
import shutil
from typing import List, Optional

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "_shared"))

from fastmcp import FastMCP

mcp = FastMCP("packages")

# ---------------------------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------------------------

async def run_command(cmd: str, cwd: Optional[str] = None) -> dict:
    """Run a command and return structured result."""
    try:
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)

        return {
            "success": process.returncode == 0,
            "returncode": process.returncode,
            "stdout": stdout.decode("utf-8", errors="replace"),
            "stderr": stderr.decode("utf-8", errors="replace"),
        }
    except asyncio.TimeoutError:
        return {
            "success": False,
            "error": "Command timed out",
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }


def find_executable(names: List[str]) -> Optional[str]:
    """Find first available executable from list."""
    for name in names:
        if shutil.which(name):
            return name
    return None


# ---------------------------------------------------------------------------
# UV Tools (Fast Python Package Manager)
# ---------------------------------------------------------------------------

@mcp.tool()
async def uv_install(
    packages: str,
    cwd: Optional[str] = None,
    dev: bool = False
) -> str:
    """
    Install Python packages using uv (fast package manager).

    Args:
        packages: Space-separated list of packages (e.g., "requests numpy pandas")
        cwd: Working directory (project root)
        dev: Install as dev dependency
    """
    if not shutil.which("uv"):
        return json.dumps({
            "success": False,
            "error": "uv not found. Install with: curl -LsSf https://astral.sh/uv/install.sh | sh",
        })

    pkg_list = packages.split()
    dev_flag = "--dev" if dev else ""

    cmd = f"uv add {dev_flag} {' '.join(pkg_list)}"
    result = await run_command(cmd, cwd)

    return json.dumps({
        "command": cmd,
        "packages": pkg_list,
        **result,
    })


@mcp.tool()
async def uv_remove(packages: str, cwd: Optional[str] = None) -> str:
    """
    Remove Python packages using uv.

    Args:
        packages: Space-separated list of packages
        cwd: Working directory
    """
    if not shutil.which("uv"):
        return json.dumps({
            "success": False,
            "error": "uv not found",
        })

    pkg_list = packages.split()
    cmd = f"uv remove {' '.join(pkg_list)}"
    result = await run_command(cmd, cwd)

    return json.dumps({
        "command": cmd,
        "packages": pkg_list,
        **result,
    })


@mcp.tool()
async def uv_sync(cwd: Optional[str] = None) -> str:
    """
    Sync project dependencies with uv.

    Args:
        cwd: Working directory (project root with pyproject.toml)
    """
    if not shutil.which("uv"):
        return json.dumps({
            "success": False,
            "error": "uv not found",
        })

    cmd = "uv sync"
    result = await run_command(cmd, cwd)

    return json.dumps({
        "command": cmd,
        **result,
    })


@mcp.tool()
async def uv_run(command: str, cwd: Optional[str] = None) -> str:
    """
    Run a command in the uv-managed environment.

    Args:
        command: Command to run (e.g., "python script.py")
        cwd: Working directory
    """
    if not shutil.which("uv"):
        return json.dumps({
            "success": False,
            "error": "uv not found",
        })

    cmd = f"uv run {command}"
    result = await run_command(cmd, cwd)

    return json.dumps({
        "command": cmd,
        **result,
    })


@mcp.tool()
async def uv_init(
    name: str,
    cwd: Optional[str] = None,
    python_version: str = "3.11"
) -> str:
    """
    Initialize a new Python project with uv.

    Args:
        name: Project name
        cwd: Parent directory for the project
        python_version: Python version to use
    """
    if not shutil.which("uv"):
        return json.dumps({
            "success": False,
            "error": "uv not found",
        })

    cmd = f"uv init {name} --python {python_version}"
    result = await run_command(cmd, cwd)

    return json.dumps({
        "command": cmd,
        "project": name,
        **result,
    })


@mcp.tool()
async def uv_venv(path: str = ".venv", python_version: Optional[str] = None) -> str:
    """
    Create a virtual environment with uv.

    Args:
        path: Path for the venv
        python_version: Python version (e.g., "3.11")
    """
    if not shutil.which("uv"):
        return json.dumps({
            "success": False,
            "error": "uv not found",
        })

    python_flag = f"--python {python_version}" if python_version else ""
    cmd = f"uv venv {path} {python_flag}"
    result = await run_command(cmd)

    return json.dumps({
        "command": cmd,
        "venv_path": path,
        **result,
    })


@mcp.tool()
async def uv_pip_install(packages: str, cwd: Optional[str] = None) -> str:
    """
    Install packages using uv pip (faster pip alternative).

    Args:
        packages: Space-separated packages
        cwd: Working directory
    """
    if not shutil.which("uv"):
        return json.dumps({
            "success": False,
            "error": "uv not found",
        })

    cmd = f"uv pip install {packages}"
    result = await run_command(cmd, cwd)

    return json.dumps({
        "command": cmd,
        **result,
    })


# ---------------------------------------------------------------------------
# Pip Tools (Standard Python)
# ---------------------------------------------------------------------------

@mcp.tool()
async def pip_install(
    packages: str,
    upgrade: bool = False,
    requirements_file: Optional[str] = None,
    cwd: Optional[str] = None
) -> str:
    """
    Install Python packages using pip.

    Args:
        packages: Space-separated list of packages
        upgrade: Upgrade packages if already installed
        requirements_file: Install from requirements file instead
        cwd: Working directory
    """
    upgrade_flag = "--upgrade" if upgrade else ""

    if requirements_file:
        cmd = f"pip install -r {requirements_file} {upgrade_flag}"
    else:
        cmd = f"pip install {packages} {upgrade_flag}"

    result = await run_command(cmd, cwd)

    return json.dumps({
        "command": cmd,
        **result,
    })


@mcp.tool()
async def pip_uninstall(packages: str, cwd: Optional[str] = None) -> str:
    """
    Uninstall Python packages.

    Args:
        packages: Space-separated packages
        cwd: Working directory
    """
    cmd = f"pip uninstall -y {packages}"
    result = await run_command(cmd, cwd)

    return json.dumps({
        "command": cmd,
        **result,
    })


@mcp.tool()
async def pip_list(outdated: bool = False, cwd: Optional[str] = None) -> str:
    """
    List installed Python packages.

    Args:
        outdated: Only show outdated packages
        cwd: Working directory
    """
    outdated_flag = "--outdated" if outdated else ""
    cmd = f"pip list --format=json {outdated_flag}"
    result = await run_command(cmd, cwd)

    if result["success"]:
        try:
            packages = json.loads(result["stdout"])
            return json.dumps({
                "success": True,
                "packages": packages,
                "total": len(packages),
            })
        except json.JSONDecodeError:
            pass

    return json.dumps(result)


@mcp.tool()
async def pip_freeze(cwd: Optional[str] = None) -> str:
    """
    Get pip freeze output (for requirements.txt).

    Args:
        cwd: Working directory
    """
    cmd = "pip freeze"
    result = await run_command(cmd, cwd)

    return json.dumps({
        "command": cmd,
        **result,
    })


# ---------------------------------------------------------------------------
# NPM/Node.js Tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def npm_install(
    packages: str = "",
    dev: bool = False,
    cwd: Optional[str] = None
) -> str:
    """
    Install Node.js packages using npm/pnpm/yarn.

    Args:
        packages: Space-separated packages (empty = install from package.json)
        dev: Install as dev dependency
        cwd: Working directory
    """
    pkg_manager = find_executable(["pnpm", "yarn", "npm"])
    if not pkg_manager:
        return json.dumps({
            "success": False,
            "error": "No Node.js package manager found (npm, pnpm, yarn)",
        })

    if packages:
        dev_flag = "-D" if dev else ""
        if pkg_manager == "yarn":
            cmd = f"yarn add {dev_flag} {packages}"
        else:
            cmd = f"{pkg_manager} add {dev_flag} {packages}"
    else:
        cmd = f"{pkg_manager} install"

    result = await run_command(cmd, cwd)

    return json.dumps({
        "command": cmd,
        "package_manager": pkg_manager,
        **result,
    })


@mcp.tool()
async def npm_remove(packages: str, cwd: Optional[str] = None) -> str:
    """
    Remove Node.js packages.

    Args:
        packages: Space-separated packages
        cwd: Working directory
    """
    pkg_manager = find_executable(["pnpm", "yarn", "npm"])
    if not pkg_manager:
        return json.dumps({
            "success": False,
            "error": "No Node.js package manager found",
        })

    if pkg_manager == "yarn":
        cmd = f"yarn remove {packages}"
    else:
        cmd = f"{pkg_manager} remove {packages}"

    result = await run_command(cmd, cwd)

    return json.dumps({
        "command": cmd,
        **result,
    })


@mcp.tool()
async def npm_run(script: str, cwd: Optional[str] = None) -> str:
    """
    Run an npm script.

    Args:
        script: Script name from package.json
        cwd: Working directory
    """
    pkg_manager = find_executable(["pnpm", "yarn", "npm"])
    if not pkg_manager:
        return json.dumps({
            "success": False,
            "error": "No Node.js package manager found",
        })

    cmd = f"{pkg_manager} run {script}"
    result = await run_command(cmd, cwd)

    return json.dumps({
        "command": cmd,
        **result,
    })


@mcp.tool()
async def npm_init(cwd: Optional[str] = None, name: Optional[str] = None) -> str:
    """
    Initialize a new Node.js project.

    Args:
        cwd: Working directory
        name: Project name
    """
    pkg_manager = find_executable(["pnpm", "yarn", "npm"])
    if not pkg_manager:
        return json.dumps({
            "success": False,
            "error": "No Node.js package manager found",
        })

    cmd = f"{pkg_manager} init -y"
    result = await run_command(cmd, cwd)

    return json.dumps({
        "command": cmd,
        **result,
    })


# ---------------------------------------------------------------------------
# Virtual Environment Tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def create_venv(
    path: str = ".venv",
    python: str = "python3"
) -> str:
    """
    Create a Python virtual environment.

    Args:
        path: Path for the virtual environment
        python: Python interpreter to use
    """
    # Prefer uv if available
    if shutil.which("uv"):
        cmd = f"uv venv {path}"
    else:
        cmd = f"{python} -m venv {path}"

    result = await run_command(cmd)

    return json.dumps({
        "command": cmd,
        "venv_path": path,
        "activate_cmd": f"source {path}/bin/activate",
        **result,
    })


@mcp.tool()
async def list_venvs(search_path: str = ".") -> str:
    """
    Find virtual environments in a directory.

    Args:
        search_path: Directory to search
    """
    import glob

    venvs = []

    # Common venv patterns
    patterns = [
        os.path.join(search_path, ".venv"),
        os.path.join(search_path, "venv"),
        os.path.join(search_path, ".env"),
        os.path.join(search_path, "*", ".venv"),
    ]

    for pattern in patterns:
        for path in glob.glob(pattern):
            if os.path.isdir(path):
                bin_dir = os.path.join(path, "bin")
                scripts_dir = os.path.join(path, "Scripts")

                if os.path.isdir(bin_dir) or os.path.isdir(scripts_dir):
                    python_path = os.path.join(
                        bin_dir if os.path.isdir(bin_dir) else scripts_dir,
                        "python"
                    )
                    venvs.append({
                        "path": path,
                        "python": python_path if os.path.exists(python_path) else None,
                    })

    return json.dumps({
        "venvs": venvs,
        "total": len(venvs),
    })


# ---------------------------------------------------------------------------
# Package Info Tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def package_info(package: str, ecosystem: str = "python") -> str:
    """
    Get information about a package.

    Args:
        package: Package name
        ecosystem: "python" or "npm"
    """
    if ecosystem == "python":
        cmd = f"pip show {package}"
    else:
        cmd = f"npm info {package} --json"

    result = await run_command(cmd)

    return json.dumps({
        "package": package,
        "ecosystem": ecosystem,
        **result,
    })


@mcp.tool()
async def search_packages(query: str, ecosystem: str = "python") -> str:
    """
    Search for packages.

    Args:
        query: Search query
        ecosystem: "python" or "npm"
    """
    if ecosystem == "python":
        # pip search is deprecated, use pypi API
        import urllib.request

        try:
            url = f"https://pypi.org/pypi/{query}/json"
            with urllib.request.urlopen(url, timeout=10) as response:
                data = json.loads(response.read().decode())
                return json.dumps({
                    "success": True,
                    "package": query,
                    "info": {
                        "name": data["info"]["name"],
                        "version": data["info"]["version"],
                        "summary": data["info"]["summary"],
                        "author": data["info"]["author"],
                    },
                })
        except Exception as e:
            return json.dumps({
                "success": False,
                "error": str(e),
            })
    else:
        cmd = f"npm search {query} --json"
        result = await run_command(cmd)
        return json.dumps(result)


if __name__ == "__main__":
    from server_entrypoint import parse_server_args, run_mcp_http_server

    args = parse_server_args(
        description="Package Server MCP Toolkit",
        default_port=8027,
        default_name="package",
    )
    run_mcp_http_server(mcp, args=args)
