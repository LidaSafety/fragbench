#!/usr/bin/env python3
"""
Git Server - Version Control Tools

Provides comprehensive git operations:
- Status, diff, log
- Staging and commits
- Branch management
- Remote operations
"""

import asyncio
import json
import os
from typing import Optional

from fastmcp import FastMCP

mcp = FastMCP("git")

# ---------------------------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------------------------


async def run_git(args: str, cwd: Optional[str] = None) -> dict:
    """Run a git command and return structured result."""
    cmd = f"git {args}"

    try:
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60)

        return {
            "success": process.returncode == 0,
            "returncode": process.returncode,
            "stdout": stdout.decode("utf-8", errors="replace"),
            "stderr": stderr.decode("utf-8", errors="replace"),
        }
    except asyncio.TimeoutError:
        return {"success": False, "error": "Command timed out"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ---------------------------------------------------------------------------
# Status & Info Tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def git_status(cwd: Optional[str] = None, short: bool = False) -> str:
    """
    Get git status of the repository.

    Args:
        cwd: Repository directory
        short: Use short format
    """
    flags = "-s" if short else ""
    result = await run_git(f"status {flags}", cwd)

    return json.dumps({
        "command": f"git status {flags}",
        **result,
    })


@mcp.tool()
async def git_diff(
    path: Optional[str] = None,
    staged: bool = False,
    cwd: Optional[str] = None
) -> str:
    """
    Show git diff.

    Args:
        path: Specific file to diff (or all if not specified)
        staged: Show staged changes (--cached)
        cwd: Repository directory
    """
    flags = "--cached" if staged else ""
    path_arg = path or ""

    result = await run_git(f"diff {flags} {path_arg}", cwd)

    return json.dumps({
        "command": f"git diff {flags} {path_arg}",
        **result,
    })


@mcp.tool()
async def git_log(
    count: int = 10,
    oneline: bool = True,
    path: Optional[str] = None,
    cwd: Optional[str] = None
) -> str:
    """
    Show git commit log.

    Args:
        count: Number of commits to show
        oneline: Use one-line format
        path: Show log for specific file
        cwd: Repository directory
    """
    format_flag = "--oneline" if oneline else "--format=medium"
    path_arg = f"-- {path}" if path else ""

    result = await run_git(f"log -{count} {format_flag} {path_arg}", cwd)

    return json.dumps({
        "command": f"git log -{count} {format_flag}",
        **result,
    })


@mcp.tool()
async def git_show(ref: str = "HEAD", cwd: Optional[str] = None) -> str:
    """
    Show a commit or object.

    Args:
        ref: Commit hash, branch, or ref to show
        cwd: Repository directory
    """
    result = await run_git(f"show {ref} --stat", cwd)

    return json.dumps({
        "command": f"git show {ref}",
        **result,
    })


@mcp.tool()
async def git_blame(path: str, cwd: Optional[str] = None) -> str:
    """
    Show who changed each line of a file.

    Args:
        path: File path
        cwd: Repository directory
    """
    result = await run_git(f"blame {path}", cwd)

    return json.dumps({
        "command": f"git blame {path}",
        **result,
    })


# ---------------------------------------------------------------------------
# Staging & Commit Tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def git_add(
    paths: str = ".",
    all_changes: bool = False,
    cwd: Optional[str] = None
) -> str:
    """
    Stage files for commit.

    Args:
        paths: Space-separated paths to add
        all_changes: Add all changes (-A)
        cwd: Repository directory
    """
    if all_changes:
        args = "-A"
    else:
        args = paths

    result = await run_git(f"add {args}", cwd)

    return json.dumps({
        "command": f"git add {args}",
        **result,
    })


@mcp.tool()
async def git_reset(
    paths: Optional[str] = None,
    hard: bool = False,
    cwd: Optional[str] = None
) -> str:
    """
    Unstage files or reset to a commit.

    Args:
        paths: Paths to unstage (or all if not specified)
        hard: Hard reset (WARNING: discards changes)
        cwd: Repository directory
    """
    if hard:
        if paths:
            return json.dumps({
                "success": False,
                "error": "Cannot use --hard with specific paths",
            })
        args = "--hard HEAD"
    else:
        args = paths or ""

    result = await run_git(f"reset {args}", cwd)

    return json.dumps({
        "command": f"git reset {args}",
        **result,
    })


@mcp.tool()
async def git_commit(
    message: str,
    all_changes: bool = False,
    cwd: Optional[str] = None
) -> str:
    """
    Create a commit.

    Args:
        message: Commit message
        all_changes: Automatically stage modified files (-a)
        cwd: Repository directory
    """
    flags = "-a" if all_changes else ""

    # Escape message for shell
    safe_message = message.replace('"', '\\"')

    result = await run_git(f'commit {flags} -m "{safe_message}"', cwd)

    return json.dumps({
        "command": f"git commit {flags} -m ...",
        "message": message,
        **result,
    })


@mcp.tool()
async def git_stash(
    action: str = "push",
    message: Optional[str] = None,
    cwd: Optional[str] = None
) -> str:
    """
    Stash changes.

    Args:
        action: push, pop, list, drop, apply
        message: Stash message (for push)
        cwd: Repository directory
    """
    if action == "push" and message:
        args = f'push -m "{message}"'
    else:
        args = action

    result = await run_git(f"stash {args}", cwd)

    return json.dumps({
        "command": f"git stash {args}",
        **result,
    })


# ---------------------------------------------------------------------------
# Branch Tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def git_branch(
    name: Optional[str] = None,
    delete: bool = False,
    list_all: bool = False,
    cwd: Optional[str] = None
) -> str:
    """
    Manage branches.

    Args:
        name: Branch name (to create or delete)
        delete: Delete the branch
        list_all: List all branches including remote
        cwd: Repository directory
    """
    if name:
        if delete:
            args = f"-d {name}"
        else:
            args = name
    else:
        args = "-a" if list_all else ""

    result = await run_git(f"branch {args}", cwd)

    return json.dumps({
        "command": f"git branch {args}",
        **result,
    })


@mcp.tool()
async def git_checkout(
    target: str,
    create: bool = False,
    cwd: Optional[str] = None
) -> str:
    """
    Switch branches or restore files.

    Args:
        target: Branch name or file path
        create: Create new branch (-b)
        cwd: Repository directory
    """
    flags = "-b" if create else ""

    result = await run_git(f"checkout {flags} {target}", cwd)

    return json.dumps({
        "command": f"git checkout {flags} {target}",
        **result,
    })


@mcp.tool()
async def git_switch(
    branch: str,
    create: bool = False,
    cwd: Optional[str] = None
) -> str:
    """
    Switch branches (modern alternative to checkout).

    Args:
        branch: Branch name
        create: Create new branch (-c)
        cwd: Repository directory
    """
    flags = "-c" if create else ""

    result = await run_git(f"switch {flags} {branch}", cwd)

    return json.dumps({
        "command": f"git switch {flags} {branch}",
        **result,
    })


@mcp.tool()
async def git_merge(
    branch: str,
    no_ff: bool = False,
    cwd: Optional[str] = None
) -> str:
    """
    Merge a branch.

    Args:
        branch: Branch to merge
        no_ff: Create merge commit even if fast-forward is possible
        cwd: Repository directory
    """
    flags = "--no-ff" if no_ff else ""

    result = await run_git(f"merge {flags} {branch}", cwd)

    return json.dumps({
        "command": f"git merge {flags} {branch}",
        **result,
    })


@mcp.tool()
async def git_rebase(
    branch: str,
    cwd: Optional[str] = None
) -> str:
    """
    Rebase current branch onto another.

    Args:
        branch: Branch to rebase onto
        cwd: Repository directory
    """
    result = await run_git(f"rebase {branch}", cwd)

    return json.dumps({
        "command": f"git rebase {branch}",
        **result,
    })


# ---------------------------------------------------------------------------
# Remote Tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def git_remote(
    action: str = "list",
    name: Optional[str] = None,
    url: Optional[str] = None,
    cwd: Optional[str] = None
) -> str:
    """
    Manage remotes.

    Args:
        action: list, add, remove, show
        name: Remote name
        url: Remote URL (for add)
        cwd: Repository directory
    """
    if action == "list":
        args = "-v"
    elif action == "add" and name and url:
        args = f"add {name} {url}"
    elif action == "remove" and name:
        args = f"remove {name}"
    elif action == "show" and name:
        args = f"show {name}"
    else:
        args = "-v"

    result = await run_git(f"remote {args}", cwd)

    return json.dumps({
        "command": f"git remote {args}",
        **result,
    })


@mcp.tool()
async def git_fetch(
    remote: str = "origin",
    prune: bool = False,
    cwd: Optional[str] = None
) -> str:
    """
    Fetch from remote.

    Args:
        remote: Remote name
        prune: Remove stale remote-tracking branches
        cwd: Repository directory
    """
    flags = "--prune" if prune else ""

    result = await run_git(f"fetch {remote} {flags}", cwd)

    return json.dumps({
        "command": f"git fetch {remote} {flags}",
        **result,
    })


@mcp.tool()
async def git_pull(
    remote: str = "origin",
    branch: Optional[str] = None,
    rebase: bool = False,
    cwd: Optional[str] = None
) -> str:
    """
    Pull from remote.

    Args:
        remote: Remote name
        branch: Branch to pull
        rebase: Use rebase instead of merge
        cwd: Repository directory
    """
    flags = "--rebase" if rebase else ""
    branch_arg = branch or ""

    result = await run_git(f"pull {flags} {remote} {branch_arg}", cwd)

    return json.dumps({
        "command": f"git pull {flags} {remote} {branch_arg}",
        **result,
    })


@mcp.tool()
async def git_push(
    remote: str = "origin",
    branch: Optional[str] = None,
    set_upstream: bool = False,
    force: bool = False,
    cwd: Optional[str] = None
) -> str:
    """
    Push to remote.

    Args:
        remote: Remote name
        branch: Branch to push
        set_upstream: Set upstream tracking (-u)
        force: Force push (use with caution!)
        cwd: Repository directory
    """
    flags = []
    if set_upstream:
        flags.append("-u")
    if force:
        flags.append("--force-with-lease")

    branch_arg = branch or ""
    flags_str = " ".join(flags)

    result = await run_git(f"push {flags_str} {remote} {branch_arg}", cwd)

    return json.dumps({
        "command": f"git push {flags_str} {remote} {branch_arg}",
        **result,
    })


@mcp.tool()
async def git_clone(
    url: str,
    directory: Optional[str] = None,
    depth: Optional[int] = None,
    cwd: Optional[str] = None
) -> str:
    """
    Clone a repository.

    Args:
        url: Repository URL
        directory: Target directory
        depth: Shallow clone depth
        cwd: Parent directory
    """
    args = url
    if directory:
        args = f"{args} {directory}"
    if depth:
        args = f"--depth {depth} {args}"

    result = await run_git(f"clone {args}", cwd)

    return json.dumps({
        "command": f"git clone {args}",
        **result,
    })


# ---------------------------------------------------------------------------
# Repository Info
# ---------------------------------------------------------------------------

@mcp.tool()
async def git_info(cwd: Optional[str] = None) -> str:
    """
    Get repository information.

    Args:
        cwd: Repository directory
    """
    info = {}

    # Current branch
    result = await run_git("branch --show-current", cwd)
    if result["success"]:
        info["branch"] = result["stdout"].strip()

    # Remote URL
    result = await run_git("remote get-url origin", cwd)
    if result["success"]:
        info["remote_url"] = result["stdout"].strip()

    # Last commit
    result = await run_git("log -1 --format=%H", cwd)
    if result["success"]:
        info["last_commit"] = result["stdout"].strip()

    # Root directory
    result = await run_git("rev-parse --show-toplevel", cwd)
    if result["success"]:
        info["root"] = result["stdout"].strip()

    # Status summary
    result = await run_git("status --porcelain", cwd)
    if result["success"]:
        lines = result["stdout"].strip().split("\n") if result["stdout"].strip() else []
        info["changed_files"] = len(lines)
        info["clean"] = len(lines) == 0

    return json.dumps({
        "success": True,
        **info,
    })


@mcp.tool()
async def git_init(
    directory: str = ".",
    bare: bool = False,
    cwd: Optional[str] = None
) -> str:
    """
    Initialize a new git repository.

    Args:
        directory: Directory to initialize
        bare: Create a bare repository
        cwd: Parent directory
    """
    flags = "--bare" if bare else ""

    result = await run_git(f"init {flags} {directory}", cwd)

    return json.dumps({
        "command": f"git init {flags} {directory}",
        **result,
    })


if __name__ == "__main__":
    from fragbench_mcp.servers.server_entrypoint import parse_server_args, run_mcp_http_server

    args = parse_server_args(
        description="Git MCP Server",
        default_port=8025,
        default_name="git",
    )
    run_mcp_http_server(mcp, args=args)
