#!/usr/bin/env python3
"""
Network Reconnaissance MCP Server for Red Team Operations.

Provides tools for:
- IP range scanning
- Port scanning & service detection
- OS fingerprinting
- Network topology mapping
"""

import asyncio
import ipaddress
import json
import re
import shutil
import socket
import subprocess
from dataclasses import dataclass
from typing import Any, Optional

from fastmcp import FastMCP

from test_mode import (
    is_test_mode,
    fake_port_scan,
    fake_nmap_scan,
    fake_ping_sweep,
    fake_masscan_scan,
    fake_service_banner,
    fake_reverse_dns,
    fake_traceroute,
    fake_whois_lookup,
)

# Initialize MCP server
mcp = FastMCP("recon-network")


@dataclass
class ScanResult:
    """Result from a network scan."""
    target: str
    open_ports: list[int]
    services: dict[int, str]
    os_guess: Optional[str] = None
    hostname: Optional[str] = None
    mac_address: Optional[str] = None


def _check_tool(tool: str) -> bool:
    """Check if a tool is available."""
    return shutil.which(tool) is not None


def _parse_nmap_output(output: str) -> dict[str, Any]:
    """Parse nmap output into structured data."""
    result = {
        "hosts": [],
        "open_ports": [],
        "services": {},
        "os_matches": [],
    }

    current_host = None

    for line in output.split("\n"):
        # Host discovery
        if "Nmap scan report for" in line:
            match = re.search(r"for\s+(\S+)", line)
            if match:
                current_host = match.group(1)
                result["hosts"].append(current_host)

        # Port info
        port_match = re.match(r"(\d+)/(tcp|udp)\s+(\w+)\s*(.*)", line)
        if port_match:
            port = int(port_match.group(1))
            protocol = port_match.group(2)
            state = port_match.group(3)
            service = port_match.group(4).strip()

            if state == "open":
                result["open_ports"].append(port)
                result["services"][port] = {
                    "protocol": protocol,
                    "state": state,
                    "service": service,
                }

        # OS detection
        if "OS:" in line or "Running:" in line:
            result["os_matches"].append(line.strip())

    return result


def _parse_masscan_output(output: str) -> dict[str, Any]:
    """Parse masscan output into structured data."""
    result = {
        "hosts": {},
        "total_open": 0,
    }

    for line in output.split("\n"):
        # Masscan output format: Discovered open port 80/tcp on 192.168.1.1
        match = re.search(r"open port (\d+)/(tcp|udp) on (\S+)", line)
        if match:
            port = int(match.group(1))
            protocol = match.group(2)
            host = match.group(3)

            if host not in result["hosts"]:
                result["hosts"][host] = []
            result["hosts"][host].append({"port": port, "protocol": protocol})
            result["total_open"] += 1

    return result


@mcp.tool()
async def ping_sweep(
    target: str,
    timeout: int = 2,
) -> str:
    """
    Perform a ping sweep to discover live hosts in a network range.

    Args:
        target: IP address, CIDR range (e.g., 192.168.1.0/24), or hostname
        timeout: Timeout in seconds per host

    Returns:
        JSON with discovered live hosts
    """
    if is_test_mode():
        return json.dumps(fake_ping_sweep(target), indent=2)

    try:
        # Validate and expand target
        if "/" in target:
            network = ipaddress.ip_network(target, strict=False)
            hosts = [str(ip) for ip in network.hosts()]
        else:
            hosts = [target]

        # Limit to reasonable size
        if len(hosts) > 256:
            hosts = hosts[:256]

        live_hosts = []

        async def ping_host(ip: str) -> Optional[str]:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "ping", "-c", "1", "-W", str(timeout), ip,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(proc.wait(), timeout=timeout + 1)
                if proc.returncode == 0:
                    return ip
            except (asyncio.TimeoutError, Exception):
                pass
            return None

        # Run pings concurrently
        tasks = [ping_host(ip) for ip in hosts]
        results = await asyncio.gather(*tasks)
        live_hosts = [ip for ip in results if ip is not None]

        return json.dumps({
            "target": target,
            "scanned": len(hosts),
            "live_hosts": live_hosts,
            "count": len(live_hosts),
        }, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def port_scan(
    target: str,
    ports: str = "21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5432,8080,8443",
    timeout: float = 1.0,
    scan_type: str = "connect",
) -> str:
    """
    Scan ports on a target host.

    Args:
        target: IP address or hostname to scan
        ports: Comma-separated ports or range (e.g., "22,80,443" or "1-1000")
        timeout: Connection timeout in seconds
        scan_type: Type of scan - "connect" (TCP connect) or "nmap" (if available)

    Returns:
        JSON with open ports and service guesses
    """
    if is_test_mode():
        return json.dumps(fake_port_scan(target, ports, scan_type=scan_type), indent=2)

    # Parse ports
    port_list = []
    for part in ports.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            port_list.extend(range(int(start), int(end) + 1))
        else:
            port_list.append(int(part))

    # Limit ports
    port_list = port_list[:1000]

    # Common service mapping
    COMMON_SERVICES = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
        993: "imaps", 995: "pop3s", 3306: "mysql", 3389: "rdp",
        5432: "postgresql", 8080: "http-proxy", 8443: "https-alt",
        27017: "mongodb", 6379: "redis", 11211: "memcached",
    }

    if scan_type == "nmap" and _check_tool("nmap"):
        # Use nmap for better results
        port_arg = ",".join(str(p) for p in port_list[:100])
        cmd = ["nmap", "-sT", "-p", port_arg, "--open", "-T4", target]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)

        result = _parse_nmap_output(stdout.decode())
        result["target"] = target
        result["scan_type"] = "nmap"
        return json.dumps(result, indent=2)

    # TCP connect scan
    open_ports = []
    services = {}

    async def check_port(port: int) -> Optional[int]:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=timeout,
            )
            writer.close()
            await writer.wait_closed()
            return port
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None

    # Scan concurrently with semaphore to limit connections
    sem = asyncio.Semaphore(100)

    async def bounded_check(port: int) -> Optional[int]:
        async with sem:
            return await check_port(port)

    tasks = [bounded_check(p) for p in port_list]
    results = await asyncio.gather(*tasks)
    open_ports = [p for p in results if p is not None]

    for port in open_ports:
        services[port] = COMMON_SERVICES.get(port, "unknown")

    return json.dumps({
        "target": target,
        "scan_type": "tcp_connect",
        "ports_scanned": len(port_list),
        "open_ports": open_ports,
        "services": services,
    }, indent=2)


@mcp.tool()
async def nmap_scan(
    target: str,
    scan_type: str = "quick",
    ports: Optional[str] = None,
    scripts: Optional[str] = None,
) -> str:
    """
    Run an nmap scan with various presets.

    Args:
        target: IP, hostname, or CIDR range to scan
        scan_type: Preset type - "quick", "full", "service", "vuln", "stealth"
        ports: Optional port specification (overrides preset)
        scripts: Optional NSE scripts to run (comma-separated)

    Returns:
        Parsed nmap results as JSON
    """
    if is_test_mode():
        return json.dumps(fake_nmap_scan(target, scan_type, ports), indent=2)

    if not _check_tool("nmap"):
        return json.dumps({"error": "nmap is not installed"})

    # Build command based on scan type
    cmd = ["nmap"]

    if scan_type == "quick":
        cmd.extend(["-T4", "-F", "--open"])
    elif scan_type == "full":
        cmd.extend(["-T4", "-p-", "--open"])
    elif scan_type == "service":
        cmd.extend(["-sV", "-T4", "--open"])
    elif scan_type == "vuln":
        cmd.extend(["-sV", "--script=vuln", "-T4"])
    elif scan_type == "stealth":
        cmd.extend(["-sS", "-T2", "--open"])
    else:
        cmd.extend(["-T4", "--open"])

    if ports:
        cmd.extend(["-p", ports])

    if scripts:
        cmd.extend(["--script", scripts])

    cmd.append(target)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)

        output = stdout.decode()
        result = _parse_nmap_output(output)
        result["target"] = target
        result["scan_type"] = scan_type
        result["command"] = " ".join(cmd)
        result["raw_output"] = output[:5000]  # Truncate for large scans

        return json.dumps(result, indent=2)

    except asyncio.TimeoutError:
        return json.dumps({"error": "Scan timed out after 5 minutes"})
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def masscan_scan(
    target: str,
    ports: str = "0-65535",
    rate: int = 1000,
) -> str:
    """
    Run a fast masscan port scan (requires masscan installed).

    Args:
        target: IP or CIDR range to scan
        ports: Port range to scan (default: all ports)
        rate: Packets per second (be careful with high rates)

    Returns:
        Discovered open ports as JSON
    """
    if is_test_mode():
        return json.dumps(fake_masscan_scan(target, ports, rate), indent=2)

    if not _check_tool("masscan"):
        return json.dumps({"error": "masscan is not installed. Install with: apt install masscan"})

    # Safety limit on rate
    rate = min(rate, 10000)

    cmd = [
        "masscan",
        target,
        "-p", ports,
        "--rate", str(rate),
        "--open",
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)

        output = stdout.decode() + stderr.decode()
        result = _parse_masscan_output(output)
        result["target"] = target
        result["ports_scanned"] = ports
        result["rate"] = rate

        return json.dumps(result, indent=2)

    except asyncio.TimeoutError:
        return json.dumps({"error": "Scan timed out"})
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def service_banner(
    target: str,
    port: int,
    timeout: float = 5.0,
) -> str:
    """
    Grab the service banner from a specific port.

    Args:
        target: IP address or hostname
        port: Port number to connect to
        timeout: Connection timeout in seconds

    Returns:
        Service banner if available
    """
    if is_test_mode():
        return json.dumps(fake_service_banner(target, port), indent=2)

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port),
            timeout=timeout,
        )

        # Send a probe depending on common services
        probes = {
            80: b"HEAD / HTTP/1.0\r\n\r\n",
            443: b"",  # SSL services need special handling
            22: b"",   # SSH sends banner first
            21: b"",   # FTP sends banner first
            25: b"",   # SMTP sends banner first
            110: b"",  # POP3 sends banner first
        }

        probe = probes.get(port, b"")
        if probe:
            writer.write(probe)
            await writer.drain()

        # Read response
        try:
            banner = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            banner_text = banner.decode("utf-8", errors="replace").strip()
        except asyncio.TimeoutError:
            banner_text = "(no banner received)"

        writer.close()
        await writer.wait_closed()

        return json.dumps({
            "target": target,
            "port": port,
            "banner": banner_text,
            "banner_length": len(banner_text),
        }, indent=2)

    except Exception as e:
        return json.dumps({
            "target": target,
            "port": port,
            "error": str(e),
        })


@mcp.tool()
async def reverse_dns(
    ip: str,
) -> str:
    """
    Perform reverse DNS lookup on an IP address.

    Args:
        ip: IP address to look up

    Returns:
        Hostname(s) associated with the IP
    """
    if is_test_mode():
        return json.dumps(fake_reverse_dns(ip), indent=2)

    try:
        hostname, aliases, _ = socket.gethostbyaddr(ip)
        return json.dumps({
            "ip": ip,
            "hostname": hostname,
            "aliases": aliases,
        }, indent=2)
    except socket.herror as e:
        return json.dumps({
            "ip": ip,
            "error": f"No PTR record: {e}",
        })
    except Exception as e:
        return json.dumps({
            "ip": ip,
            "error": str(e),
        })


@mcp.tool()
async def traceroute(
    target: str,
    max_hops: int = 30,
) -> str:
    """
    Trace the network path to a target.

    Args:
        target: IP address or hostname
        max_hops: Maximum number of hops to trace

    Returns:
        Network path with hop information
    """
    if is_test_mode():
        return json.dumps(fake_traceroute(target, max_hops), indent=2)

    if not _check_tool("traceroute"):
        return json.dumps({"error": "traceroute is not installed"})

    cmd = ["traceroute", "-m", str(max_hops), "-w", "2", target]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)

        output = stdout.decode()
        hops = []

        for line in output.split("\n"):
            # Parse traceroute output
            match = re.match(r"\s*(\d+)\s+(.+)", line)
            if match:
                hop_num = int(match.group(1))
                hop_info = match.group(2).strip()
                hops.append({
                    "hop": hop_num,
                    "info": hop_info,
                })

        return json.dumps({
            "target": target,
            "hops": hops,
            "total_hops": len(hops),
        }, indent=2)

    except asyncio.TimeoutError:
        return json.dumps({"error": "Traceroute timed out"})
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def whois_lookup(
    target: str,
) -> str:
    """
    Perform a WHOIS lookup on a domain or IP.

    Args:
        target: Domain name or IP address

    Returns:
        WHOIS registration information
    """
    if is_test_mode():
        return json.dumps(fake_whois_lookup(target), indent=2)

    if not _check_tool("whois"):
        return json.dumps({"error": "whois is not installed"})

    try:
        proc = await asyncio.create_subprocess_exec(
            "whois", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)

        output = stdout.decode()

        # Extract key fields
        fields = {}
        for line in output.split("\n"):
            if ":" in line and not line.strip().startswith("%"):
                key, _, value = line.partition(":")
                key = key.strip().lower().replace(" ", "_")
                value = value.strip()
                if key and value and key not in fields:
                    fields[key] = value

        return json.dumps({
            "target": target,
            "parsed_fields": fields,
            "raw_output": output[:3000],
        }, indent=2)

    except asyncio.TimeoutError:
        return json.dumps({"error": "WHOIS lookup timed out"})
    except Exception as e:
        return json.dumps({"error": str(e)})


if __name__ == "__main__":
    from fragbench_mcp.servers.server_entrypoint import parse_server_args, run_mcp_http_server

    args = parse_server_args(
        description="Network Reconnaissance MCP Server",
        default_port=8021,
        default_name="recon-network",
    )
    run_mcp_http_server(mcp, args=args)
