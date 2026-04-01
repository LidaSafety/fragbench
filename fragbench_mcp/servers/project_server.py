#!/usr/bin/env python3
"""
Project Server - Project Scaffolding and Management

Provides project creation and management:
- Project scaffolding for various frameworks
- Build and test execution
- Docker and deployment tools
- Project analysis
"""

import asyncio
import json
import os
import shutil
from pathlib import Path
from typing import Dict, List, Optional

from fastmcp import FastMCP

mcp = FastMCP("project")

# ---------------------------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------------------------

async def run_command(cmd: str, cwd: Optional[str] = None, timeout: int = 300) -> dict:
    """Run a command and return structured result."""
    try:
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)

        return {
            "success": process.returncode == 0,
            "returncode": process.returncode,
            "stdout": stdout.decode("utf-8", errors="replace"),
            "stderr": stderr.decode("utf-8", errors="replace"),
        }
    except asyncio.TimeoutError:
        return {"success": False, "error": f"Command timed out after {timeout}s"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ---------------------------------------------------------------------------
# Project Scaffolding
# ---------------------------------------------------------------------------

PROJECT_STRUCTURES: Dict[str, Dict] = {
    "python_package": {
        "directories": ["src/{name}", "tests", "docs"],
        "files": {
            "pyproject.toml": '''[project]
name = "{name}"
version = "0.1.0"
description = "{description}"
requires-python = ">=3.11"
dependencies = []

[project.optional-dependencies]
dev = ["pytest", "ruff", "mypy"]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.ruff]
line-length = 100
''',
            "src/{name}/__init__.py": '''"""
{description}
"""

__version__ = "0.1.0"
''',
            "tests/__init__.py": "",
            "tests/test_{name}.py": '''"""Tests for {name}"""

import pytest


def test_import():
    """Test that the package can be imported."""
    import {name}
    assert {name}.__version__
''',
            "README.md": '''# {name}

{description}

## Installation

```bash
pip install {name}
```

## Usage

```python
import {name}
```
''',
            ".gitignore": '''__pycache__/
*.py[cod]
*$py.class
.venv/
dist/
*.egg-info/
.ruff_cache/
.mypy_cache/
.pytest_cache/
''',
        },
    },

    "fastapi_app": {
        "directories": ["app", "app/routers", "app/models", "tests"],
        "files": {
            "pyproject.toml": '''[project]
name = "{name}"
version = "0.1.0"
description = "{description}"
requires-python = ">=3.11"
dependencies = [
    "fastapi>=0.100.0",
    "uvicorn[standard]>=0.23.0",
    "pydantic>=2.0.0",
]

[project.optional-dependencies]
dev = ["pytest", "httpx", "ruff"]
''',
            "app/__init__.py": "",
            "app/main.py": '''"""
{description}
"""

from fastapi import FastAPI

app = FastAPI(title="{name}", version="0.1.0")


@app.get("/")
async def root():
    return {{"message": "Welcome to {name}"}}


@app.get("/health")
async def health():
    return {{"status": "healthy"}}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
''',
            "app/routers/__init__.py": "",
            "app/models/__init__.py": "",
            "tests/__init__.py": "",
            "tests/test_main.py": '''"""Tests for main app."""

import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_root():
    response = client.get("/")
    assert response.status_code == 200


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
''',
            "Dockerfile": '''FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml .
RUN pip install .

COPY . .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
''',
            ".gitignore": '''__pycache__/
*.py[cod]
.venv/
.env
''',
        },
    },

    "mcp_server": {
        "directories": ["servers", "tests"],
        "files": {
            "pyproject.toml": '''[project]
name = "{name}"
version = "0.1.0"
description = "{description}"
requires-python = ">=3.11"
dependencies = [
    "mcp>=0.1.0",
    "fastmcp>=0.1.0",
]

[project.optional-dependencies]
dev = ["pytest"]
''',
            "servers/__init__.py": "",
            "servers/main.py": '''#!/usr/bin/env python3
"""
{description}
"""

import json
from typing import Optional

from fastmcp import FastMCP

mcp = FastMCP("{name}")


@mcp.tool()
async def hello(name: str = "World") -> str:
    """
    Say hello.

    Args:
        name: Name to greet
    """
    return json.dumps({{"message": f"Hello, {{name}}!"}})


if __name__ == "__main__":
    from fragbench_mcp.servers.server_entrypoint import parse_server_args, run_mcp_http_server

    args = parse_server_args(
        description="Project Scaffolding MCP Server",
        default_port=8037,
        default_name="project",
    )
    run_mcp_http_server(mcp, args=args)
''',
            "tests/__init__.py": "",
            "README.md": '''# {name}

{description}

## Usage

```bash
python servers/main.py
```
''',
            ".gitignore": '''__pycache__/
*.py[cod]
.venv/
''',
        },
    },

    "typescript_lib": {
        "directories": ["src", "tests"],
        "files": {
            "package.json": '''{
  "name": "{name}",
  "version": "0.1.0",
  "description": "{description}",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "scripts": {
    "build": "tsc",
    "test": "jest",
    "lint": "eslint src"
  },
  "devDependencies": {
    "typescript": "^5.0.0",
    "@types/node": "^20.0.0",
    "jest": "^29.0.0",
    "@types/jest": "^29.0.0",
    "ts-jest": "^29.0.0"
  }
}
''',
            "tsconfig.json": '''{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "declaration": true,
    "outDir": "./dist",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist"]
}
''',
            "src/index.ts": '''/**
 * {description}
 */

export function hello(name: string = "World"): string {
  return `Hello, ${name}!`;
}

export default { hello };
''',
            ".gitignore": '''node_modules/
dist/
*.log
''',
        },
    },
}


@mcp.tool()
async def create_project(
    name: str,
    template: str,
    directory: Optional[str] = None,
    description: str = ""
) -> str:
    """
    Create a new project from a template.

    Args:
        name: Project name
        template: Template type (python_package, fastapi_app, mcp_server, typescript_lib)
        directory: Parent directory (default: current)
        description: Project description
    """
    if template not in PROJECT_STRUCTURES:
        return json.dumps({
            "success": False,
            "error": f"Unknown template: {template}",
            "available": list(PROJECT_STRUCTURES.keys()),
        })

    structure = PROJECT_STRUCTURES[template]
    base_dir = os.path.join(directory or ".", name)

    if os.path.exists(base_dir):
        return json.dumps({
            "success": False,
            "error": f"Directory already exists: {base_dir}",
        })

    try:
        # Create base directory
        os.makedirs(base_dir)

        # Create subdirectories
        for dir_template in structure.get("directories", []):
            dir_path = dir_template.format(name=name)
            os.makedirs(os.path.join(base_dir, dir_path), exist_ok=True)

        # Create files
        created_files = []
        for file_template, content_template in structure.get("files", {}).items():
            file_path = file_template.format(name=name)
            full_path = os.path.join(base_dir, file_path)

            # Create parent directory if needed
            os.makedirs(os.path.dirname(full_path) or ".", exist_ok=True)

            # Format content
            content = content_template.format(
                name=name,
                description=description or f"A {template} project",
            )

            with open(full_path, "w", encoding="utf-8") as f:
                f.write(content)

            created_files.append(file_path)

        return json.dumps({
            "success": True,
            "project": name,
            "template": template,
            "path": os.path.abspath(base_dir),
            "files": created_files,
        })

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
        })


@mcp.tool()
async def list_project_templates() -> str:
    """List available project templates."""
    templates = []
    for name, structure in PROJECT_STRUCTURES.items():
        templates.append({
            "name": name,
            "directories": structure.get("directories", []),
            "files": list(structure.get("files", {}).keys()),
        })

    return json.dumps({
        "templates": templates,
    })


# ---------------------------------------------------------------------------
# Build & Test Tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def run_tests(
    cwd: Optional[str] = None,
    verbose: bool = False,
    pattern: Optional[str] = None
) -> str:
    """
    Run project tests.

    Args:
        cwd: Project directory
        verbose: Verbose output
        pattern: Test file pattern
    """
    work_dir = cwd or "."

    # Detect test framework
    if os.path.exists(os.path.join(work_dir, "pyproject.toml")) or \
       os.path.exists(os.path.join(work_dir, "pytest.ini")):
        # Python project
        flags = "-v" if verbose else ""
        pattern_arg = pattern or ""
        cmd = f"pytest {flags} {pattern_arg}"
    elif os.path.exists(os.path.join(work_dir, "package.json")):
        # Node project
        cmd = "npm test"
    else:
        return json.dumps({
            "success": False,
            "error": "Could not detect project type",
        })

    result = await run_command(cmd, work_dir)

    return json.dumps({
        "command": cmd,
        **result,
    })


@mcp.tool()
async def build_project(cwd: Optional[str] = None) -> str:
    """
    Build the project.

    Args:
        cwd: Project directory
    """
    work_dir = cwd or "."

    # Detect project type
    if os.path.exists(os.path.join(work_dir, "pyproject.toml")):
        cmd = "python -m build"
    elif os.path.exists(os.path.join(work_dir, "package.json")):
        cmd = "npm run build"
    elif os.path.exists(os.path.join(work_dir, "Cargo.toml")):
        cmd = "cargo build --release"
    elif os.path.exists(os.path.join(work_dir, "go.mod")):
        cmd = "go build ./..."
    else:
        return json.dumps({
            "success": False,
            "error": "Could not detect project type",
        })

    result = await run_command(cmd, work_dir, timeout=600)

    return json.dumps({
        "command": cmd,
        **result,
    })


@mcp.tool()
async def run_script(
    script: str,
    cwd: Optional[str] = None
) -> str:
    """
    Run a project script (npm run / python -m).

    Args:
        script: Script name
        cwd: Project directory
    """
    work_dir = cwd or "."

    if os.path.exists(os.path.join(work_dir, "package.json")):
        cmd = f"npm run {script}"
    else:
        cmd = f"python -m {script}"

    result = await run_command(cmd, work_dir)

    return json.dumps({
        "command": cmd,
        **result,
    })


# ---------------------------------------------------------------------------
# Docker Tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def docker_build(
    tag: str,
    dockerfile: str = "Dockerfile",
    cwd: Optional[str] = None
) -> str:
    """
    Build a Docker image.

    Args:
        tag: Image tag
        dockerfile: Dockerfile path
        cwd: Build context directory
    """
    cmd = f"docker build -t {tag} -f {dockerfile} ."
    result = await run_command(cmd, cwd, timeout=600)

    return json.dumps({
        "command": cmd,
        **result,
    })


@mcp.tool()
async def docker_run(
    image: str,
    name: Optional[str] = None,
    ports: Optional[str] = None,
    detach: bool = True,
    env: Optional[str] = None
) -> str:
    """
    Run a Docker container.

    Args:
        image: Image name/tag
        name: Container name
        ports: Port mapping (e.g., "8000:8000")
        detach: Run in background
        env: Environment variables (JSON object)
    """
    flags = []
    if detach:
        flags.append("-d")
    if name:
        flags.append(f"--name {name}")
    if ports:
        flags.append(f"-p {ports}")

    if env:
        try:
            env_dict = json.loads(env)
            for k, v in env_dict.items():
                flags.append(f"-e {k}={v}")
        except json.JSONDecodeError:
            pass

    cmd = f"docker run {' '.join(flags)} {image}"
    result = await run_command(cmd)

    return json.dumps({
        "command": cmd,
        **result,
    })


@mcp.tool()
async def docker_compose_up(
    file: str = "docker-compose.yaml",
    detach: bool = True,
    build: bool = False,
    cwd: Optional[str] = None
) -> str:
    """
    Start docker-compose services.

    Args:
        file: Compose file path
        detach: Run in background
        build: Build images before starting
        cwd: Working directory
    """
    flags = []
    if detach:
        flags.append("-d")
    if build:
        flags.append("--build")

    cmd = f"docker compose -f {file} up {' '.join(flags)}"
    result = await run_command(cmd, cwd, timeout=300)

    return json.dumps({
        "command": cmd,
        **result,
    })


@mcp.tool()
async def docker_compose_down(
    file: str = "docker-compose.yaml",
    volumes: bool = False,
    cwd: Optional[str] = None
) -> str:
    """
    Stop docker-compose services.

    Args:
        file: Compose file path
        volumes: Remove volumes
        cwd: Working directory
    """
    flags = "-v" if volumes else ""
    cmd = f"docker compose -f {file} down {flags}"
    result = await run_command(cmd, cwd)

    return json.dumps({
        "command": cmd,
        **result,
    })


# ---------------------------------------------------------------------------
# Project Analysis
# ---------------------------------------------------------------------------

@mcp.tool()
async def analyze_project(cwd: Optional[str] = None) -> str:
    """
    Analyze project structure and configuration.

    Args:
        cwd: Project directory
    """
    work_dir = cwd or "."

    analysis = {
        "path": os.path.abspath(work_dir),
        "type": "unknown",
        "config_files": [],
        "directories": [],
        "file_counts": {},
    }

    # Detect project type
    if os.path.exists(os.path.join(work_dir, "pyproject.toml")):
        analysis["type"] = "python"
        analysis["config_files"].append("pyproject.toml")
    if os.path.exists(os.path.join(work_dir, "package.json")):
        analysis["type"] = "node"
        analysis["config_files"].append("package.json")
    if os.path.exists(os.path.join(work_dir, "Cargo.toml")):
        analysis["type"] = "rust"
        analysis["config_files"].append("Cargo.toml")
    if os.path.exists(os.path.join(work_dir, "go.mod")):
        analysis["type"] = "go"
        analysis["config_files"].append("go.mod")

    # Check for common config files
    common_configs = [
        ".gitignore", ".env", "Dockerfile", "docker-compose.yaml",
        "Makefile", ".github", "README.md", "requirements.txt",
    ]
    for config in common_configs:
        if os.path.exists(os.path.join(work_dir, config)):
            analysis["config_files"].append(config)

    # Count files by extension
    for root, dirs, files in os.walk(work_dir):
        # Skip hidden and common ignored directories
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ["node_modules", "__pycache__", "venv", ".venv", "dist", "build"]]

        for file in files:
            ext = Path(file).suffix.lower() or "no_ext"
            analysis["file_counts"][ext] = analysis["file_counts"].get(ext, 0) + 1

    # Get top-level directories
    try:
        for entry in os.listdir(work_dir):
            if os.path.isdir(os.path.join(work_dir, entry)) and not entry.startswith("."):
                analysis["directories"].append(entry)
    except OSError:
        pass

    return json.dumps({
        "success": True,
        **analysis,
    })


@mcp.tool()
async def count_lines(
    cwd: Optional[str] = None,
    extensions: str = ".py,.js,.ts"
) -> str:
    """
    Count lines of code in project.

    Args:
        cwd: Project directory
        extensions: Comma-separated list of extensions to count
    """
    work_dir = cwd or "."
    ext_list = [e.strip() for e in extensions.split(",")]

    counts = {}
    total_lines = 0
    total_files = 0

    for root, dirs, files in os.walk(work_dir):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ["node_modules", "__pycache__", "venv", ".venv"]]

        for file in files:
            ext = Path(file).suffix.lower()
            if ext not in ext_list:
                continue

            filepath = os.path.join(root, file)
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    lines = len(f.readlines())

                counts[ext] = counts.get(ext, 0) + lines
                total_lines += lines
                total_files += 1
            except (IOError, OSError):
                continue

    return json.dumps({
        "success": True,
        "by_extension": counts,
        "total_lines": total_lines,
        "total_files": total_files,
    })


if __name__ == "__main__":
    mcp.run()
