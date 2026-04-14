#!/usr/bin/env python3
"""Network reconnaissance simulation MCP server."""

from __future__ import annotations

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "_shared"))

import ipaddress
import json
import random
from typing import List

from fastmcp import FastMCP

mcp = FastMCP("network")


@mcp.tool()
def scan_subnet(cidr: str, service_ports: List[int] | None = None, max_hosts: int = 16) -> str:
    """Generate simulated scan results for a subnet."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        return json.dumps({"success": False, "error": str(exc)})

    ports = service_ports or [22, 80, 443, 3389]
    hosts = list(network.hosts())[: max(1, min(max_hosts, 64))]
    results = []
    for host in hosts:
        if random.random() < 0.45:
            open_ports = [p for p in ports if random.random() < 0.35]
            if open_ports:
                results.append({"host": str(host), "ports": sorted(set(open_ports))})
    return json.dumps({"success": True, "mode": "simulated", "cidr": cidr, "results": results})


@mcp.tool()
def summarize_exposure(scan_json: str) -> str:
    """Summarize scan findings in a compact report."""
    try:
        payload = json.loads(scan_json)
        results = payload.get("results", [])
    except Exception as exc:
        return json.dumps({"success": False, "error": f"invalid scan payload: {exc}"})

    unique_ports = sorted({port for row in results for port in row.get("ports", [])})
    return json.dumps(
        {
            "success": True,
            "hosts_found": len(results),
            "services_exposed": unique_ports,
            "risk_hint": "review remote access and web admin exposure",
        }
    )


if __name__ == "__main__":
    from server_entrypoint import parse_server_args, run_mcp_http_server
    args = parse_server_args(description="Network recon MCP server", default_port=8014)
    run_mcp_http_server(mcp, args=args)
