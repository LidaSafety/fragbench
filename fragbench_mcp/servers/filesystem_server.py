#!/usr/bin/env python3
"""
Filesystem Server - File System Operations

Provides comprehensive file system tools:
- File reading and writing
- Directory operations
- File searching and globbing
- File metadata and permissions
"""

import argparse
import fnmatch
import glob as glob_module
import json
import os
import shutil
import stat
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Mount, Route

mcp = FastMCP("filesystem")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB max read
MAX_LINES = 10000


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Filesystem MCP server")
    parser.add_argument(
        "--transport",
        default="stdio",
        choices=["stdio", "http", "streamable-http", "sse"],
        help="Transport to use for the MCP server",
    )
    parser.add_argument("--host", default="127.0.0.1", help="HTTP bind host")
    parser.add_argument("--port", type=int, default=8001, help="HTTP bind port")
    parser.add_argument("--path", default="/mcp", help="HTTP MCP endpoint path")
    parser.add_argument(
        "--log-level",
        default="info",
        help="Uvicorn log level for HTTP transports",
    )
    parser.add_argument(
        "--json-response",
        action="store_true",
        help="Prefer JSON responses for HTTP MCP calls when supported",
    )
    parser.add_argument(
        "--stateless-http",
        action="store_true",
        help="Enable stateless mode for streamable HTTP transport",
    )
    parser.add_argument(
        "--no-browser-page",
        action="store_true",
        help="Do not expose browser-friendly / and GET /mcp informational routes",
    )
    return parser.parse_args()


def _build_info_app(
    server_name: str,
    transport: str,
    host: str,
    port: int,
    path: str,
    json_response: bool,
    stateless_http: bool,
) -> Starlette:
    normalized_path = path if path.startswith("/") else f"/{path}"
    endpoint_url = f"http://{host}:{port}{normalized_path}"
    info_path = f"{normalized_path.rstrip('/')}/info" if normalized_path != "/" else "/info"

    async def index(_: Request) -> Response:
        return JSONResponse(
            {
                "server": server_name,
                "status": "ok",
                "transport": transport,
                "mcp_endpoint": endpoint_url,
                "notes": [
                    "Use an MCP client against the endpoint above.",
                    "A browser GET to the MCP endpoint is informational only.",
                    "For Streamable HTTP, clients typically POST JSON-RPC to the MCP endpoint.",
                ],
            }
        )

    async def health(_: Request) -> Response:
        return JSONResponse({"status": "ok", "server": server_name})

    async def mcp_info(_: Request) -> Response:
        return PlainTextResponse(
            f"{server_name} MCP server is running.\n"
            f"Transport: {transport}\n"
            f"Endpoint: {endpoint_url}\n"
            f"Info page: {info_path}\n"
            "Use an MCP client for protocol calls; this page is informational only.\n"
        )

    inner_app = mcp.http_app(
        path="/",
        transport=transport,
        json_response=json_response,
        stateless_http=stateless_http,
    )

    return Starlette(
        routes=[
            Route("/", endpoint=index, methods=["GET"]),
            Route("/health", endpoint=health, methods=["GET"]),
            # Keep the MCP endpoint unshadowed so POST/DELETE reach the transport app.
            Route(info_path, endpoint=mcp_info, methods=["GET"]),
            Mount(normalized_path, app=inner_app),
        ],
        lifespan=inner_app.lifespan,
    )


def _run_server() -> None:
    args = _parse_args()

    if args.transport == "stdio":
        mcp.run()
        return

    normalized_path = args.path if args.path.startswith("/") else f"/{args.path}"

    if args.no_browser_page:
        mcp.run(
            transport=args.transport,
            host=args.host,
            port=args.port,
            path=normalized_path,
            log_level=args.log_level,
            json_response=args.json_response,
            stateless_http=args.stateless_http,
        )
        return

    app = _build_info_app(
        server_name="filesystem",
        transport=args.transport,
        host=args.host,
        port=args.port,
        path=normalized_path,
        json_response=args.json_response,
        stateless_http=args.stateless_http,
    )

    import uvicorn

    uvicorn.run(app, host=args.host, port=args.port, log_level=args.log_level)

# ---------------------------------------------------------------------------
# File Reading Tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def read_file(
    path: str,
    offset: int = 0,
    limit: Optional[int] = None,
    encoding: str = "utf-8"
) -> str:
    """
    Read contents of a file.

    Args:
        path: Path to file
        offset: Line number to start from (0-indexed)
        limit: Maximum number of lines to read
        encoding: File encoding (default: utf-8)
    """
    expanded = os.path.expanduser(path)

    if not os.path.exists(expanded):
        return json.dumps({
            "success": False,
            "error": f"File not found: {path}",
        })

    if not os.path.isfile(expanded):
        return json.dumps({
            "success": False,
            "error": f"Not a file: {path}",
        })

    # Check file size
    size = os.path.getsize(expanded)
    if size > MAX_FILE_SIZE:
        return json.dumps({
            "success": False,
            "error": f"File too large: {size} bytes (max {MAX_FILE_SIZE})",
        })

    try:
        with open(expanded, "r", encoding=encoding, errors="replace") as f:
            lines = f.readlines()

        total_lines = len(lines)

        # Apply offset and limit
        if offset > 0:
            lines = lines[offset:]

        if limit:
            lines = lines[:limit]

        content = "".join(lines)

        return json.dumps({
            "success": True,
            "path": expanded,
            "content": content,
            "total_lines": total_lines,
            "returned_lines": len(lines),
            "offset": offset,
            "size": size,
        })

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
        })


@mcp.tool()
async def read_file_bytes(path: str, offset: int = 0, length: int = 1024) -> str:
    """
    Read raw bytes from a file (useful for binary files).

    Args:
        path: Path to file
        offset: Byte offset to start from
        length: Number of bytes to read
    """
    expanded = os.path.expanduser(path)

    if not os.path.exists(expanded):
        return json.dumps({
            "success": False,
            "error": f"File not found: {path}",
        })

    try:
        with open(expanded, "rb") as f:
            f.seek(offset)
            data = f.read(length)

        return json.dumps({
            "success": True,
            "path": expanded,
            "offset": offset,
            "length": len(data),
            "data_hex": data.hex(),
            "data_preview": data[:100].decode("utf-8", errors="replace"),
        })

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
        })


# ---------------------------------------------------------------------------
# File Writing Tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def write_file(
    path: str,
    content: str,
    create_dirs: bool = True,
    encoding: str = "utf-8"
) -> str:
    """
    Write content to a file (creates or overwrites).

    Args:
        path: Path to file
        content: Content to write
        create_dirs: Create parent directories if needed
        encoding: File encoding
    """
    expanded = os.path.expanduser(path)

    try:
        if create_dirs:
            os.makedirs(os.path.dirname(expanded) or ".", exist_ok=True)

        with open(expanded, "w", encoding=encoding) as f:
            f.write(content)

        return json.dumps({
            "success": True,
            "path": expanded,
            "bytes_written": len(content.encode(encoding)),
        })

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
        })


@mcp.tool()
async def append_file(path: str, content: str, encoding: str = "utf-8") -> str:
    """
    Append content to a file.

    Args:
        path: Path to file
        content: Content to append
        encoding: File encoding
    """
    expanded = os.path.expanduser(path)

    try:
        with open(expanded, "a", encoding=encoding) as f:
            f.write(content)

        return json.dumps({
            "success": True,
            "path": expanded,
            "bytes_appended": len(content.encode(encoding)),
        })

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
        })


@mcp.tool()
async def edit_file(
    path: str,
    old_text: str,
    new_text: str,
    replace_all: bool = False
) -> str:
    """
    Edit a file by replacing text.

    Args:
        path: Path to file
        old_text: Text to find
        new_text: Text to replace with
        replace_all: Replace all occurrences (default: first only)
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

        if old_text not in content:
            return json.dumps({
                "success": False,
                "error": "Text not found in file",
            })

        if replace_all:
            count = content.count(old_text)
            new_content = content.replace(old_text, new_text)
        else:
            count = 1
            new_content = content.replace(old_text, new_text, 1)

        with open(expanded, "w", encoding="utf-8") as f:
            f.write(new_content)

        return json.dumps({
            "success": True,
            "path": expanded,
            "replacements": count,
        })

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
        })


# ---------------------------------------------------------------------------
# Directory Operations
# ---------------------------------------------------------------------------

@mcp.tool()
async def list_directory(
    path: str = ".",
    show_hidden: bool = False,
    recursive: bool = False
) -> str:
    """
    List contents of a directory.

    Args:
        path: Directory path
        show_hidden: Include hidden files
        recursive: List recursively
    """
    expanded = os.path.expanduser(path)

    if not os.path.exists(expanded):
        return json.dumps({
            "success": False,
            "error": f"Directory not found: {path}",
        })

    if not os.path.isdir(expanded):
        return json.dumps({
            "success": False,
            "error": f"Not a directory: {path}",
        })

    try:
        entries = []

        if recursive:
            for root, dirs, files in os.walk(expanded):
                if not show_hidden:
                    dirs[:] = [d for d in dirs if not d.startswith(".")]
                    files = [f for f in files if not f.startswith(".")]

                for name in dirs + files:
                    full_path = os.path.join(root, name)
                    rel_path = os.path.relpath(full_path, expanded)
                    is_dir = os.path.isdir(full_path)

                    entries.append({
                        "name": rel_path,
                        "type": "directory" if is_dir else "file",
                        "size": os.path.getsize(full_path) if not is_dir else None,
                    })

                if len(entries) > 1000:
                    break
        else:
            for name in os.listdir(expanded):
                if not show_hidden and name.startswith("."):
                    continue

                full_path = os.path.join(expanded, name)
                is_dir = os.path.isdir(full_path)

                entries.append({
                    "name": name,
                    "type": "directory" if is_dir else "file",
                    "size": os.path.getsize(full_path) if not is_dir else None,
                })

        return json.dumps({
            "success": True,
            "path": expanded,
            "entries": sorted(entries, key=lambda x: (x["type"] != "directory", x["name"])),
            "total": len(entries),
        })

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
        })


@mcp.tool()
async def create_directory(path: str, parents: bool = True) -> str:
    """
    Create a directory.

    Args:
        path: Directory path to create
        parents: Create parent directories if needed
    """
    expanded = os.path.expanduser(path)

    try:
        if parents:
            os.makedirs(expanded, exist_ok=True)
        else:
            os.mkdir(expanded)

        return json.dumps({
            "success": True,
            "path": expanded,
        })

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
        })


@mcp.tool()
async def delete_path(path: str, recursive: bool = False) -> str:
    """
    Delete a file or directory.

    Args:
        path: Path to delete
        recursive: Delete directories recursively
    """
    expanded = os.path.expanduser(path)

    if not os.path.exists(expanded):
        return json.dumps({
            "success": False,
            "error": f"Path not found: {path}",
        })

    try:
        if os.path.isdir(expanded):
            if recursive:
                shutil.rmtree(expanded)
            else:
                os.rmdir(expanded)
        else:
            os.remove(expanded)

        return json.dumps({
            "success": True,
            "deleted": expanded,
        })

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
        })


@mcp.tool()
async def copy_path(src: str, dst: str) -> str:
    """
    Copy a file or directory.

    Args:
        src: Source path
        dst: Destination path
    """
    src_exp = os.path.expanduser(src)
    dst_exp = os.path.expanduser(dst)

    if not os.path.exists(src_exp):
        return json.dumps({
            "success": False,
            "error": f"Source not found: {src}",
        })

    try:
        if os.path.isdir(src_exp):
            shutil.copytree(src_exp, dst_exp)
        else:
            shutil.copy2(src_exp, dst_exp)

        return json.dumps({
            "success": True,
            "src": src_exp,
            "dst": dst_exp,
        })

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
        })


@mcp.tool()
async def move_path(src: str, dst: str) -> str:
    """
    Move/rename a file or directory.

    Args:
        src: Source path
        dst: Destination path
    """
    src_exp = os.path.expanduser(src)
    dst_exp = os.path.expanduser(dst)

    if not os.path.exists(src_exp):
        return json.dumps({
            "success": False,
            "error": f"Source not found: {src}",
        })

    try:
        shutil.move(src_exp, dst_exp)

        return json.dumps({
            "success": True,
            "src": src_exp,
            "dst": dst_exp,
        })

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
        })


# ---------------------------------------------------------------------------
# File Search Tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def glob_files(pattern: str, path: str = ".") -> str:
    """
    Find files matching a glob pattern.

    Args:
        pattern: Glob pattern (e.g., "**/*.py")
        path: Base directory
    """
    expanded = os.path.expanduser(path)

    try:
        full_pattern = os.path.join(expanded, pattern)
        matches = glob_module.glob(full_pattern, recursive=True)

        results = []
        for match in matches[:500]:  # Limit results
            is_dir = os.path.isdir(match)
            results.append({
                "path": match,
                "type": "directory" if is_dir else "file",
                "size": os.path.getsize(match) if not is_dir else None,
            })

        return json.dumps({
            "success": True,
            "pattern": pattern,
            "base": expanded,
            "matches": results,
            "total": len(matches),
        })

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
        })


@mcp.tool()
async def search_in_files(
    pattern: str,
    path: str = ".",
    file_pattern: str = "*",
    max_results: int = 100
) -> str:
    """
    Search for text pattern in files.

    Args:
        pattern: Text pattern to search for
        path: Base directory
        file_pattern: Glob pattern for files to search
        max_results: Maximum number of results
    """
    import re

    expanded = os.path.expanduser(path)

    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        return json.dumps({
            "success": False,
            "error": f"Invalid regex: {e}",
        })

    results = []

    try:
        for root, _, files in os.walk(expanded):
            for filename in files:
                if not fnmatch.fnmatch(filename, file_pattern):
                    continue

                filepath = os.path.join(root, filename)

                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        for line_num, line in enumerate(f, 1):
                            if regex.search(line):
                                results.append({
                                    "file": filepath,
                                    "line": line_num,
                                    "content": line.strip()[:200],
                                })

                                if len(results) >= max_results:
                                    break
                except (IOError, OSError):
                    continue

                if len(results) >= max_results:
                    break

            if len(results) >= max_results:
                break

        return json.dumps({
            "success": True,
            "pattern": pattern,
            "results": results,
            "total": len(results),
            "truncated": len(results) >= max_results,
        })

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
        })


# ---------------------------------------------------------------------------
# File Metadata
# ---------------------------------------------------------------------------

@mcp.tool()
async def file_info(path: str) -> str:
    """
    Get detailed information about a file or directory.

    Args:
        path: Path to inspect
    """
    expanded = os.path.expanduser(path)

    if not os.path.exists(expanded):
        return json.dumps({
            "success": False,
            "error": f"Path not found: {path}",
        })

    try:
        stat_info = os.stat(expanded)
        is_dir = os.path.isdir(expanded)

        info = {
            "path": expanded,
            "type": "directory" if is_dir else "file",
            "size": stat_info.st_size,
            "created": datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
            "accessed": datetime.fromtimestamp(stat_info.st_atime).isoformat(),
            "permissions": oct(stat_info.st_mode)[-3:],
            "owner_uid": stat_info.st_uid,
            "group_gid": stat_info.st_gid,
        }

        if not is_dir:
            # Try to detect file type
            import mimetypes
            mime_type, _ = mimetypes.guess_type(expanded)
            info["mime_type"] = mime_type

        return json.dumps({
            "success": True,
            **info,
        })

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
        })


@mcp.tool()
async def change_permissions(path: str, mode: str) -> str:
    """
    Change file permissions.

    Args:
        path: Path to file/directory
        mode: Octal permission mode (e.g., "755")
    """
    expanded = os.path.expanduser(path)

    if not os.path.exists(expanded):
        return json.dumps({
            "success": False,
            "error": f"Path not found: {path}",
        })

    try:
        os.chmod(expanded, int(mode, 8))

        return json.dumps({
            "success": True,
            "path": expanded,
            "mode": mode,
        })

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
        })


if __name__ == "__main__":
    _run_server()
