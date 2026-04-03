#!/usr/bin/env python3
"""
Code Server - Code Generation and Manipulation

Provides intelligent code tools:
- File creation with templates
- Code formatting and linting
- Import management
- Code analysis
"""

import asyncio
import json
import os
import re
import shutil
from pathlib import Path
from typing import Dict, List, Optional

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "_shared"))

from fastmcp import FastMCP

mcp = FastMCP("code")

# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------

TEMPLATES: Dict[str, str] = {
    "python_script": '''#!/usr/bin/env python3
"""
{description}
"""

def main():
    pass


if __name__ == "__main__":
    main()
''',

    "python_class": '''"""
{description}
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class {class_name}:
    """{description}"""

    def __init__(self):
        pass
''',

    "python_fastapi": '''"""
{description}
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="{name}", description="{description}")


class Item(BaseModel):
    name: str
    value: str


@app.get("/")
async def root():
    return {{"message": "Hello World"}}


@app.get("/items/{{item_id}}")
async def get_item(item_id: int):
    return {{"item_id": item_id}}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
''',

    "python_test": '''"""
Tests for {module}
"""

import pytest


class Test{class_name}:
    """Tests for {class_name}"""

    def setup_method(self):
        """Set up test fixtures."""
        pass

    def test_example(self):
        """Example test."""
        assert True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
''',

    "python_mcp_server": '''#!/usr/bin/env python3
"""
{description}
"""

import json
from typing import Optional

from fastmcp import FastMCP

mcp = FastMCP("{name}")


@mcp.tool()
async def example_tool(param: str) -> str:
    """
    Example tool.

    Args:
        param: Example parameter
    """
    return json.dumps({{"result": param}})


if __name__ == "__main__":
    from server_entrypoint import parse_server_args, run_mcp_http_server

    args = parse_server_args(
        description="Code Server MCP Toolkit",
        default_port=8026,
        default_name="code",
    )
    run_mcp_http_server(mcp, args=args)
''',

    "typescript_module": '''/**
 * {description}
 */

export interface {interface_name} {{
  id: string;
  name: string;
}}

export class {class_name} {{
  constructor() {{
    // Initialize
  }}
}}

export default {class_name};
''',

    "react_component": '''import React from 'react';

interface {name}Props {{
  title?: string;
}}

export const {name}: React.FC<{name}Props> = ({{ title = "{name}" }}) => {{
  return (
    <div className="{name_lower}">
      <h1>{{title}}</h1>
    </div>
  );
}};

export default {name};
''',

    "dockerfile": '''FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["python", "main.py"]
''',

    "docker_compose": '''version: '3.8'

services:
  app:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - .:/app
    environment:
      - DEBUG=true
''',
}


# ---------------------------------------------------------------------------
# File Creation Tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def create_file(
    path: str,
    content: str,
    create_dirs: bool = True
) -> str:
    """
    Create a new file with content.

    Args:
        path: File path to create
        content: File content
        create_dirs: Create parent directories if needed
    """
    expanded = os.path.expanduser(path)

    if os.path.exists(expanded):
        return json.dumps({
            "success": False,
            "error": f"File already exists: {path}",
        })

    try:
        if create_dirs:
            os.makedirs(os.path.dirname(expanded) or ".", exist_ok=True)

        with open(expanded, "w", encoding="utf-8") as f:
            f.write(content)

        return json.dumps({
            "success": True,
            "path": expanded,
            "bytes": len(content),
        })

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
        })


@mcp.tool()
async def create_from_template(
    path: str,
    template: str,
    variables: str = "{}"
) -> str:
    """
    Create a file from a template.

    Args:
        path: File path to create
        template: Template name (python_script, python_class, python_fastapi,
                  python_test, python_mcp_server, typescript_module,
                  react_component, dockerfile, docker_compose)
        variables: JSON string of template variables
    """
    if template not in TEMPLATES:
        return json.dumps({
            "success": False,
            "error": f"Unknown template: {template}",
            "available": list(TEMPLATES.keys()),
        })

    try:
        vars_dict = json.loads(variables)
    except json.JSONDecodeError:
        vars_dict = {}

    # Add defaults
    vars_dict.setdefault("name", Path(path).stem)
    vars_dict.setdefault("description", f"Auto-generated {template}")
    vars_dict.setdefault("class_name", vars_dict["name"].title().replace("_", ""))
    vars_dict.setdefault("interface_name", f"I{vars_dict['class_name']}")
    vars_dict.setdefault("name_lower", vars_dict["name"].lower())
    vars_dict.setdefault("module", vars_dict["name"])

    try:
        content = TEMPLATES[template].format(**vars_dict)
    except KeyError as e:
        return json.dumps({
            "success": False,
            "error": f"Missing template variable: {e}",
        })

    return await create_file(path, content)


@mcp.tool()
async def list_templates() -> str:
    """List available code templates."""
    return json.dumps({
        "templates": list(TEMPLATES.keys()),
    })


# ---------------------------------------------------------------------------
# Code Formatting Tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def format_code(
    path: str,
    formatter: str = "auto"
) -> str:
    """
    Format a code file.

    Args:
        path: File to format
        formatter: Formatter to use (auto, black, ruff, prettier)
    """
    expanded = os.path.expanduser(path)

    if not os.path.exists(expanded):
        return json.dumps({
            "success": False,
            "error": f"File not found: {path}",
        })

    ext = Path(expanded).suffix.lower()

    # Auto-detect formatter
    if formatter == "auto":
        if ext == ".py":
            formatter = "ruff" if shutil.which("ruff") else "black"
        elif ext in (".js", ".ts", ".jsx", ".tsx", ".json", ".css", ".md"):
            formatter = "prettier"
        else:
            return json.dumps({
                "success": False,
                "error": f"No formatter for extension: {ext}",
            })

    # Build command
    if formatter == "ruff":
        cmd = f"ruff format {expanded}"
    elif formatter == "black":
        cmd = f"black {expanded}"
    elif formatter == "prettier":
        cmd = f"npx prettier --write {expanded}"
    else:
        return json.dumps({
            "success": False,
            "error": f"Unknown formatter: {formatter}",
        })

    try:
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

        return json.dumps({
            "success": process.returncode == 0,
            "formatter": formatter,
            "path": expanded,
            "stdout": stdout.decode(),
            "stderr": stderr.decode(),
        })

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
        })


@mcp.tool()
async def lint_code(path: str, linter: str = "auto") -> str:
    """
    Lint a code file.

    Args:
        path: File to lint
        linter: Linter to use (auto, ruff, flake8, eslint)
    """
    expanded = os.path.expanduser(path)

    if not os.path.exists(expanded):
        return json.dumps({
            "success": False,
            "error": f"File not found: {path}",
        })

    ext = Path(expanded).suffix.lower()

    # Auto-detect linter
    if linter == "auto":
        if ext == ".py":
            linter = "ruff" if shutil.which("ruff") else "flake8"
        elif ext in (".js", ".ts", ".jsx", ".tsx"):
            linter = "eslint"
        else:
            return json.dumps({
                "success": False,
                "error": f"No linter for extension: {ext}",
            })

    # Build command
    if linter == "ruff":
        cmd = f"ruff check {expanded} --output-format=json"
    elif linter == "flake8":
        cmd = f"flake8 {expanded}"
    elif linter == "eslint":
        cmd = f"npx eslint {expanded} --format json"
    else:
        return json.dumps({
            "success": False,
            "error": f"Unknown linter: {linter}",
        })

    try:
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

        return json.dumps({
            "success": process.returncode == 0,
            "linter": linter,
            "path": expanded,
            "issues": stdout.decode(),
            "stderr": stderr.decode(),
        })

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
        })


# ---------------------------------------------------------------------------
# Import Management
# ---------------------------------------------------------------------------

@mcp.tool()
async def add_import(
    path: str,
    import_statement: str
) -> str:
    """
    Add an import statement to a Python file.

    Args:
        path: Python file path
        import_statement: Import to add (e.g., "from typing import List")
    """
    expanded = os.path.expanduser(path)

    if not os.path.exists(expanded):
        return json.dumps({
            "success": False,
            "error": f"File not found: {path}",
        })

    try:
        with open(expanded, "r", encoding="utf-8") as f:
            content = f.read()

        # Check if import already exists
        if import_statement in content:
            return json.dumps({
                "success": True,
                "message": "Import already exists",
            })

        lines = content.split("\n")

        # Find the right place to insert
        insert_idx = 0
        in_docstring = False
        docstring_char = None

        for i, line in enumerate(lines):
            stripped = line.strip()

            # Track docstrings
            if not in_docstring:
                if stripped.startswith('"""') or stripped.startswith("'''"):
                    in_docstring = True
                    docstring_char = stripped[:3]
                    if stripped.count(docstring_char) >= 2:
                        in_docstring = False
            else:
                if docstring_char in stripped:
                    in_docstring = False
                continue

            if in_docstring:
                continue

            # Skip shebang and docstrings at start
            if i == 0 and stripped.startswith("#!"):
                insert_idx = i + 1
                continue

            # Find last import
            if stripped.startswith("import ") or stripped.startswith("from "):
                insert_idx = i + 1

        # Insert the import
        lines.insert(insert_idx, import_statement)

        with open(expanded, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        return json.dumps({
            "success": True,
            "path": expanded,
            "import": import_statement,
            "line": insert_idx + 1,
        })

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
        })


@mcp.tool()
async def organize_imports(path: str) -> str:
    """
    Organize imports in a Python file using isort or ruff.

    Args:
        path: Python file path
    """
    expanded = os.path.expanduser(path)

    if not os.path.exists(expanded):
        return json.dumps({
            "success": False,
            "error": f"File not found: {path}",
        })

    # Use ruff if available, otherwise isort
    if shutil.which("ruff"):
        cmd = f"ruff check --select I --fix {expanded}"
    elif shutil.which("isort"):
        cmd = f"isort {expanded}"
    else:
        return json.dumps({
            "success": False,
            "error": "Neither ruff nor isort found",
        })

    try:
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

        return json.dumps({
            "success": process.returncode == 0,
            "path": expanded,
            "stdout": stdout.decode(),
        })

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
        })


# ---------------------------------------------------------------------------
# Code Analysis
# ---------------------------------------------------------------------------

@mcp.tool()
async def analyze_code(path: str) -> str:
    """
    Analyze a code file and return structure information.

    Args:
        path: File to analyze
    """
    expanded = os.path.expanduser(path)

    if not os.path.exists(expanded):
        return json.dumps({
            "success": False,
            "error": f"File not found: {path}",
        })

    ext = Path(expanded).suffix.lower()

    try:
        with open(expanded, "r", encoding="utf-8") as f:
            content = f.read()

        lines = content.split("\n")
        analysis = {
            "path": expanded,
            "extension": ext,
            "lines": len(lines),
            "characters": len(content),
            "blank_lines": sum(1 for l in lines if not l.strip()),
        }

        if ext == ".py":
            # Python-specific analysis
            analysis["imports"] = []
            analysis["functions"] = []
            analysis["classes"] = []

            for i, line in enumerate(lines, 1):
                stripped = line.strip()

                if stripped.startswith("import ") or stripped.startswith("from "):
                    analysis["imports"].append({"line": i, "statement": stripped})

                if stripped.startswith("def "):
                    match = re.match(r"def\s+(\w+)", stripped)
                    if match:
                        analysis["functions"].append({"line": i, "name": match.group(1)})

                if stripped.startswith("class "):
                    match = re.match(r"class\s+(\w+)", stripped)
                    if match:
                        analysis["classes"].append({"line": i, "name": match.group(1)})

        return json.dumps({
            "success": True,
            **analysis,
        })

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
        })


@mcp.tool()
async def find_todos(path: str = ".", pattern: str = "**/*.py") -> str:
    """
    Find TODO/FIXME comments in code.

    Args:
        path: Base directory
        pattern: Glob pattern for files
    """
    import glob

    expanded = os.path.expanduser(path)
    todos = []

    todo_pattern = re.compile(r"#\s*(TODO|FIXME|XXX|HACK|NOTE)[\s:]*(.+)", re.IGNORECASE)

    for filepath in glob.glob(os.path.join(expanded, pattern), recursive=True):
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for i, line in enumerate(f, 1):
                    match = todo_pattern.search(line)
                    if match:
                        todos.append({
                            "file": filepath,
                            "line": i,
                            "type": match.group(1).upper(),
                            "message": match.group(2).strip(),
                        })
        except (IOError, OSError):
            continue

        if len(todos) > 500:
            break

    return json.dumps({
        "success": True,
        "todos": todos,
        "total": len(todos),
    })


if __name__ == "__main__":
    from server_entrypoint import parse_server_args, run_mcp_http_server

    args = parse_server_args(
        description="Code Server MCP Toolkit",
        default_port=8026,
        default_name="code",
    )
    run_mcp_http_server(mcp, args=args)
