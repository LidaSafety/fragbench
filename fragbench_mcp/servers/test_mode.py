#!/usr/bin/env python3
"""
Test Mode Utilities for MCP Servers.

When test mode is enabled (via MCP_TEST_MODE=true environment variable),
servers return fake but realistic-looking responses instead of executing
real operations.
"""

import ipaddress
import os
import sys
import random
from typing import Any, Optional

import logging
logging.basicConfig(filename='/tmp/test_mode.log', level=logging.DEBUG)
logging.debug("LOADING test_mode.py")

def is_test_mode() -> bool:
    """Check if test mode is enabled via environment variable."""
    return os.environ.get("MCP_TEST_MODE", "").lower() == "true"


# Common ports with service names and typical banners
COMMON_PORTS = {
    21: ("ftp", "220 FTP Server ready"),
    22: ("ssh", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"),
    23: ("telnet", ""),
    25: ("smtp", "220 mail.example.com ESMTP Postfix"),
    53: ("dns", ""),
    80: ("http", "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0"),
    110: ("pop3", "+OK POP3 server ready"),
    143: ("imap", "* OK IMAP4rev1 Service Ready"),
    443: ("https", ""),
    445: ("microsoft-ds", ""),
    993: ("imaps", ""),
    995: ("pop3s", ""),
    3306: ("mysql", "5.7.42-0ubuntu0.18.04.1"),
    3389: ("ms-wbt-server", ""),
    5432: ("postgresql", ""),
    6379: ("redis", "-ERR unknown command"),
    8080: ("http-proxy", "HTTP/1.1 200 OK\r\nServer: Apache-Coyote/1.1"),
    8443: ("https-alt", ""),
    27017: ("mongodb", ""),
}


def parse_port_spec(ports: str) -> list[int]:
    """Parse a port specification string into a list of ports."""
    port_list = []
    for part in ports.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            port_list.extend(range(int(start), int(end) + 1))
        else:
            port_list.append(int(part))
    return port_list


def fake_port_scan(
    target: str,
    ports: str = "21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5432,8080,8443",
    open_probability: float = 0.5,
    scan_type: str = "tcp_connect",
) -> dict[str, Any]:
    """
    Generate fake port scan results.

    Args:
        target: Target IP/hostname
        ports: Port specification string (e.g., "22,80,443" or "1-1000")
        open_probability: Probability (0-1) that each port is open. Default 10%.
        scan_type: Type of scan for the response

    Returns:
        Dict matching real port_scan output format
    """
    port_list = parse_port_spec(ports)
    open_ports = []
    services = {}

    for port in port_list:
        if random.random() < open_probability:
            open_ports.append(port)
            service_name = COMMON_PORTS.get(port, (f"unknown-{port}", ""))[0]
            services[port] = service_name
    logging.debug(f"OPEN PORTS: {open_ports}")

    return {
        "target": target,
        "scan_type": scan_type,
        "ports_scanned": len(port_list),
        "open_ports": sorted(open_ports),
        "services": services,
    }


def fake_nmap_scan(
    target: str,
    scan_type: str = "quick",
    ports: Optional[str] = None,
    open_probability: float = 0.1,
) -> dict[str, Any]:
    """
    Generate fake nmap scan results.

    Args:
        target: Target IP/hostname
        scan_type: Scan type preset
        ports: Optional port specification
        open_probability: Probability each port is open

    Returns:
        Dict matching real nmap_scan output format
    """
    # Determine ports based on scan type
    if ports:
        port_list = parse_port_spec(ports)
    elif scan_type == "quick":
        # Quick scan uses top 100 ports - simulate with common ones
        port_list = list(COMMON_PORTS.keys())
    elif scan_type == "full":
        # Full scan - just use common ports for simulation
        port_list = list(COMMON_PORTS.keys())
    else:
        port_list = list(COMMON_PORTS.keys())

    open_ports = []
    services = {}
    hosts = []

    for port in port_list:
        if random.random() < open_probability:
            open_ports.append(port)
            svc_name, _ = COMMON_PORTS.get(port, ("unknown", ""))
            services[port] = {
                "protocol": "tcp",
                "state": "open",
                "service": svc_name,
            }

    if open_ports:
        hosts.append(target)

    return {
        "target": target,
        "scan_type": scan_type,
        "hosts": hosts,
        "open_ports": sorted(open_ports),
        "services": services,
        "os_matches": [],
        "command": f"nmap -{_scan_type_flags(scan_type)} {target}",
        "raw_output": _fake_nmap_output(target, open_ports, services),
    }


def _scan_type_flags(scan_type: str) -> str:
    """Get nmap flags for a scan type."""
    flags = {
        "quick": "T4 -F --open",
        "full": "T4 -p- --open",
        "service": "sV -T4 --open",
        "vuln": "sV --script=vuln -T4",
        "stealth": "sS -T2 --open",
    }
    return flags.get(scan_type, "T4 --open")


def _fake_nmap_output(target: str, open_ports: list[int], services: dict) -> str:
    """Generate fake raw nmap output."""
    lines = [
        f"Starting Nmap 7.94 ( https://nmap.org )",
        f"Nmap scan report for {target}",
        f"Host is up (0.015s latency).",
    ]
    if open_ports:
        lines.append("")
        lines.append("PORT     STATE SERVICE")
        for port in sorted(open_ports):
            svc = services.get(port, {})
            svc_name = svc.get("service", "unknown") if isinstance(svc, dict) else svc
            lines.append(f"{port}/tcp  open  {svc_name}")
    else:
        lines.append("All scanned ports are closed or filtered.")
    lines.append("")
    lines.append("Nmap done: 1 IP address (1 host up)")
    return "\n".join(lines)


def fake_service_banner(target: str, port: int) -> dict[str, Any]:
    """Generate fake service banner grab results."""
    banner = ""
    if port in COMMON_PORTS:
        _, banner = COMMON_PORTS[port]

    return {
        "target": target,
        "port": port,
        "banner": banner,
        "banner_length": len(banner),
    }


def fake_ping_sweep(target: str, live_probability: float = 0.1) -> dict[str, Any]:
    """Generate fake ping sweep results."""
    live_hosts = []
    scanned = 0

    try:
        if "/" in target:
            network = ipaddress.ip_network(target, strict=False)
            hosts = [str(ip) for ip in network.hosts()][:256]
            scanned = len(hosts)
            for ip in hosts:
                if random.random() < live_probability:
                    live_hosts.append(ip)
        else:
            scanned = 1
            if random.random() < live_probability:
                live_hosts.append(target)
    except ValueError:
        scanned = 1

    return {
        "target": target,
        "scanned": scanned,
        "live_hosts": live_hosts,
        "count": len(live_hosts),
    }


def fake_masscan_scan(
    target: str,
    ports: str = "0-65535",
    rate: int = 1000,
    open_probability: float = 0.05,
) -> dict[str, Any]:
    """Generate fake masscan results."""
    # Masscan returns results grouped by host
    hosts = {}
    total_open = 0

    # For simulation, just check common ports
    for port, (svc, _) in COMMON_PORTS.items():
        if random.random() < open_probability:
            if target not in hosts:
                hosts[target] = []
            hosts[target].append({"port": port, "protocol": "tcp"})
            total_open += 1

    return {
        "target": target,
        "hosts": hosts,
        "total_open": total_open,
        "ports_scanned": ports,
        "rate": rate,
    }


def fake_reverse_dns(ip: str) -> dict[str, Any]:
    """Generate fake reverse DNS results."""
    return {
        "ip": ip,
        "hostname": "",
        "aliases": [],
    }


def fake_traceroute(target: str, max_hops: int = 30) -> dict[str, Any]:
    """Generate fake traceroute results."""
    return {
        "target": target,
        "hops": [],
        "total_hops": 0,
    }


def fake_whois_lookup(target: str) -> dict[str, Any]:
    """Generate fake WHOIS results."""
    return {
        "target": target,
        "parsed_fields": {},
        "raw_output": "",
    }

print(fake_port_scan(target='10.10.10.55'))
