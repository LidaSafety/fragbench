"""
MCP server configuration loader.

Discovers and parses MCP server configs from standard locations
(Claude Desktop, .mcp.json project files, or explicitly provided paths)
and returns ready-to-use MCPServerConfig objects.

Supported config format (same as Claude Desktop and .mcp.json):
    {
        "mcpServers": {
            "server-name": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                "env": {"API_KEY": "${MY_API_KEY}"}
            }
        }
    }
"""

from __future__ import annotations

import json
import logging
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class MCPServerConfig:
    """
    Configuration for a single MCP server process.

    Attributes:
        command:      Executable to run (e.g. "npx", "python", "uvx").
        args:         Command-line arguments passed to the executable.
        env:          Extra environment variables merged into the subprocess env.
        name:         Optional server name; used as the namespacing key.
        source:       Human-readable origin of this config (file path or label).
        required_env: Env var names that must be set for the server to function.
                      Derived automatically from "${VAR}" patterns in env values.
        auto_enable:  Whether the caller should connect without explicit inclusion.
    """

    command: str
    args: List[str] = field(default_factory=list)
    env: Optional[Dict[str, str]] = None
    name: Optional[str] = None
    source: str = "unknown"
    required_env: List[str] = field(default_factory=list)
    auto_enable: bool = True

    def is_available(self) -> bool:
        """
        Return True if every required environment variable is currently set
        and the command binary can be found on PATH.
        """
        for var in self.required_env:
            if not os.getenv(var):
                return False
        return shutil.which(self.command) is not None


# ---------------------------------------------------------------------------
# Config discovery
# ---------------------------------------------------------------------------

def _standard_config_paths() -> List[Path]:
    """Return candidate config file paths in priority order."""
    candidates: List[Path] = []

    # 1. Project-level .mcp.json (current working directory and its parents)
    cwd = Path.cwd()
    for parent in [cwd, *cwd.parents]:
        p = parent / ".mcp.json"
        candidates.append(p)
        if parent == parent.parent:
            break

    # 2. Claude Desktop app configs
    home = Path.home()
    candidates += [
        # macOS
        home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
        # Linux (XDG)
        Path(os.environ.get("XDG_CONFIG_HOME", home / ".config")) / "claude" / "claude_desktop_config.json",
        # Generic home
        home / ".claude" / "claude_desktop_config.json",
        home / ".claude" / "config.json",
        home / ".config" / "claude" / "claude_desktop_config.json",
    ]

    # 3. Windows APPDATA
    appdata = os.environ.get("APPDATA")
    if appdata:
        candidates.append(Path(appdata) / "Claude" / "claude_desktop_config.json")

    return candidates


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _extract_required_env(env: Optional[Dict[str, str]]) -> List[str]:
    """
    Scan env values for ${VAR_NAME} patterns and return the variable names.

    Example: {"KEY": "${MY_API_KEY}"} → ["MY_API_KEY"]
    """
    if not env:
        return []
    import re
    required: List[str] = []
    for value in env.values():
        for match in re.finditer(r"\$\{([^}]+)\}", str(value)):
            var = match.group(1)
            if var not in required:
                required.append(var)
    return required


def _resolve_env_values(env: Optional[Dict[str, str]]) -> Optional[Dict[str, str]]:
    """
    Expand ${VAR} placeholders in env values using the current environment.

    Unresolvable placeholders are left as-is.
    """
    if not env:
        return env
    import re
    resolved: Dict[str, str] = {}
    for key, value in env.items():
        def replacer(m: "re.Match[str]") -> str:
            return os.environ.get(m.group(1), m.group(0))
        resolved[key] = re.sub(r"\$\{([^}]+)\}", replacer, str(value))
    return resolved


def _parse_mcp_servers(
    raw: Dict,
    source: str,
    auto_enable: bool,
) -> Dict[str, MCPServerConfig]:
    """
    Parse a dict that may contain a top-level "mcpServers" key.

    Returns a mapping of server-name → MCPServerConfig.
    Skips malformed entries with a warning rather than raising.
    """
    servers_raw = raw.get("mcpServers") or raw.get("mcp_servers") or {}
    if not isinstance(servers_raw, dict):
        logger.warning("Config at '%s' has a non-dict mcpServers value — skipping.", source)
        return {}

    result: Dict[str, MCPServerConfig] = {}
    for name, entry in servers_raw.items():
        if not isinstance(entry, dict):
            logger.warning("Skipping malformed entry '%s' in '%s'.", name, source)
            continue
        command = entry.get("command")
        if not command:
            logger.warning("Skipping entry '%s' in '%s': missing 'command'.", name, source)
            continue

        raw_env: Optional[Dict[str, str]] = entry.get("env") or None
        required = _extract_required_env(raw_env)
        resolved_env = _resolve_env_values(raw_env)

        result[name] = MCPServerConfig(
            command=command,
            args=list(entry.get("args", [])),
            env=resolved_env,
            name=name,
            source=source,
            required_env=required,
            auto_enable=auto_enable,
        )

    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_mcp_configs(
    config_paths: Optional[List[str]] = None,
    include_servers: Optional[List[str]] = None,
    exclude_servers: Optional[List[str]] = None,
    only_available: bool = True,
    auto_enable: bool = True,
) -> Dict[str, MCPServerConfig]:
    """
    Discover and load MCP server configurations.

    Args:
        config_paths:    Explicit list of JSON config file paths to load.
                         When None or empty the standard locations are searched.
        include_servers: If provided, only servers whose names appear in this
                         list are returned (case-sensitive).
        exclude_servers: Server names to skip.
        only_available:  When True, servers whose required env vars are missing
                         or whose command is not on PATH are filtered out.
        auto_enable:     Value to set on every returned MCPServerConfig.

    Returns:
        Dict mapping server name → MCPServerConfig. Later configs override
        earlier ones when the same name appears in multiple files.
    """
    if config_paths:
        paths_to_search = [Path(p).expanduser() for p in config_paths]
    else:
        paths_to_search = _standard_config_paths()

    all_servers: Dict[str, MCPServerConfig] = {}

    for path in paths_to_search:
        if not path.exists():
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Could not read MCP config at '%s': %s", path, exc)
            continue

        parsed = _parse_mcp_servers(raw, source=str(path), auto_enable=auto_enable)
        if parsed:
            logger.debug("Loaded %d server(s) from '%s'.", len(parsed), path)
        all_servers.update(parsed)

    # Apply include / exclude filters
    if include_servers:
        include_set = set(include_servers)
        all_servers = {k: v for k, v in all_servers.items() if k in include_set}

    if exclude_servers:
        exclude_set = set(exclude_servers)
        all_servers = {k: v for k, v in all_servers.items() if k not in exclude_set}

    if only_available:
        all_servers = {k: v for k, v in all_servers.items() if v.is_available()}

    logger.info(
        "load_mcp_configs: returning %d server(s) (only_available=%s).",
        len(all_servers),
        only_available,
    )
    return all_servers
