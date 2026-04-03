#!/usr/bin/env python3
"""
Subdomain Enumeration MCP Server for Red Team Operations.

Provides tools for:
- DNS enumeration
- Subdomain discovery (brute-force, certificate transparency)
- DNS record lookups
- Zone transfer attempts
"""

import asyncio
import dns.resolver
import dns.zone
import dns.query
import dns.rdatatype
import json
import re
import shutil
import ssl
import socket
from typing import Any, Optional
from urllib import request, error

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "_shared"))

from fastmcp import FastMCP

# Initialize MCP server
mcp = FastMCP("recon-subdomain")


# Common subdomain wordlist
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "ns3", "ns4", "imap", "test", "blog", "dev", "api", "admin", "portal",
    "vpn", "remote", "server", "email", "mx", "cloud", "git", "svn", "web",
    "www2", "secure", "shop", "store", "mobile", "m", "app", "apps", "beta",
    "staging", "stage", "prod", "production", "demo", "cdn", "static", "media",
    "images", "img", "assets", "css", "js", "api2", "api1", "v1", "v2",
    "status", "monitor", "grafana", "prometheus", "kibana", "elastic",
    "jenkins", "ci", "cd", "build", "deploy", "docker", "k8s", "kubernetes",
    "db", "database", "mysql", "postgres", "redis", "mongo", "mongodb",
    "auth", "login", "sso", "oauth", "iam", "identity", "ldap", "ad",
    "internal", "intranet", "corp", "corporate", "private", "public",
    "support", "help", "helpdesk", "ticket", "tickets", "jira", "confluence",
    "wiki", "docs", "documentation", "forum", "forums", "community",
    "chat", "slack", "teams", "zoom", "meet", "calendar", "crm", "erp",
    "hr", "finance", "accounting", "billing", "pay", "payment", "payments",
    "download", "downloads", "upload", "uploads", "file", "files", "share",
    "backup", "backups", "archive", "archives", "old", "new", "legacy",
    "proxy", "gateway", "firewall", "router", "switch", "lb", "loadbalancer",
    "vpn2", "ipsec", "openvpn", "wireguard", "rdp", "ssh", "sftp",
]


def _check_tool(tool: str) -> bool:
    """Check if a tool is available."""
    return shutil.which(tool) is not None


async def _resolve_dns(domain: str, record_type: str = "A") -> list[str]:
    """Resolve DNS records for a domain."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10

        answers = await asyncio.to_thread(
            resolver.resolve, domain, record_type
        )
        return [str(rdata) for rdata in answers]
    except Exception:
        return []


@mcp.tool()
async def dns_lookup(
    domain: str,
    record_types: str = "A,AAAA,MX,NS,TXT,SOA,CNAME",
) -> str:
    """
    Perform DNS lookups for various record types.

    Args:
        domain: Domain name to look up
        record_types: Comma-separated list of record types

    Returns:
        DNS records found for the domain
    """
    types = [t.strip().upper() for t in record_types.split(",")]
    results = {}

    for rtype in types:
        try:
            records = await _resolve_dns(domain, rtype)
            if records:
                results[rtype] = records
        except Exception as e:
            results[rtype] = {"error": str(e)}

    return json.dumps({
        "domain": domain,
        "records": results,
    }, indent=2)


@mcp.tool()
async def subdomain_bruteforce(
    domain: str,
    wordlist: Optional[str] = None,
    concurrency: int = 50,
    timeout: float = 3.0,
) -> str:
    """
    Brute-force subdomain discovery.

    Args:
        domain: Base domain to enumerate (e.g., example.com)
        wordlist: Optional comma-separated list of subdomains to try
        concurrency: Number of concurrent lookups
        timeout: DNS query timeout in seconds

    Returns:
        Discovered subdomains with their IP addresses
    """
    if wordlist:
        subdomains = [s.strip() for s in wordlist.split(",")]
    else:
        subdomains = COMMON_SUBDOMAINS

    found = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout * 2

    sem = asyncio.Semaphore(concurrency)

    async def check_subdomain(sub: str) -> Optional[dict]:
        fqdn = f"{sub}.{domain}"
        async with sem:
            try:
                answers = await asyncio.to_thread(resolver.resolve, fqdn, "A")
                ips = [str(rdata) for rdata in answers]
                return {"subdomain": fqdn, "ips": ips}
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                return None
            except dns.exception.Timeout:
                return None
            except Exception:
                return None

    tasks = [check_subdomain(sub) for sub in subdomains]
    results = await asyncio.gather(*tasks)
    found = [r for r in results if r is not None]

    return json.dumps({
        "domain": domain,
        "checked": len(subdomains),
        "found": len(found),
        "subdomains": found,
    }, indent=2)


@mcp.tool()
async def zone_transfer(
    domain: str,
) -> str:
    """
    Attempt a DNS zone transfer (AXFR) on a domain.

    Args:
        domain: Domain to attempt zone transfer on

    Returns:
        Zone data if transfer succeeds, error otherwise
    """
    # First get NS records
    try:
        ns_records = await _resolve_dns(domain, "NS")
    except Exception as e:
        return json.dumps({"error": f"Could not get NS records: {e}"})

    if not ns_records:
        return json.dumps({"error": "No NS records found"})

    results = {
        "domain": domain,
        "nameservers": ns_records,
        "transfer_results": [],
    }

    for ns in ns_records:
        ns = ns.rstrip(".")
        try:
            zone = await asyncio.to_thread(
                dns.zone.from_xfr,
                dns.query.xfr(ns, domain, timeout=10)
            )

            records = []
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        records.append({
                            "name": str(name),
                            "type": dns.rdatatype.to_text(rdataset.rdtype),
                            "data": str(rdata),
                        })

            results["transfer_results"].append({
                "nameserver": ns,
                "success": True,
                "records": records[:100],  # Limit output
                "total_records": len(records),
            })
        except dns.exception.FormError:
            results["transfer_results"].append({
                "nameserver": ns,
                "success": False,
                "error": "Zone transfer refused (FormError)",
            })
        except Exception as e:
            results["transfer_results"].append({
                "nameserver": ns,
                "success": False,
                "error": str(e),
            })

    return json.dumps(results, indent=2)


@mcp.tool()
async def certificate_transparency(
    domain: str,
    include_expired: bool = False,
) -> str:
    """
    Query Certificate Transparency logs for subdomains.
    Uses crt.sh API.

    Args:
        domain: Domain to search for
        include_expired: Include expired certificates

    Returns:
        Subdomains found in CT logs
    """
    url = f"https://crt.sh/?q=%.{domain}&output=json"

    try:
        req = request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with request.urlopen(req, timeout=30) as response:
            data = json.loads(response.read().decode())
    except error.HTTPError as e:
        return json.dumps({"error": f"HTTP error: {e.code}"})
    except error.URLError as e:
        return json.dumps({"error": f"URL error: {e.reason}"})
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON response from crt.sh"})
    except Exception as e:
        return json.dumps({"error": str(e)})

    # Extract unique subdomains
    subdomains = set()
    for entry in data:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lower()
            # Remove wildcard prefix
            if name.startswith("*."):
                name = name[2:]
            if name.endswith(domain) or name == domain:
                subdomains.add(name)

    return json.dumps({
        "domain": domain,
        "source": "crt.sh",
        "total_certificates": len(data),
        "unique_subdomains": len(subdomains),
        "subdomains": sorted(subdomains),
    }, indent=2)


@mcp.tool()
async def reverse_ip_lookup(
    ip: str,
) -> str:
    """
    Find domains hosted on an IP address using various sources.

    Args:
        ip: IP address to look up

    Returns:
        Domains/hostnames associated with the IP
    """
    results = {
        "ip": ip,
        "sources": {},
    }

    # PTR record lookup
    try:
        ptr_records = await _resolve_dns(
            ".".join(reversed(ip.split("."))) + ".in-addr.arpa",
            "PTR"
        )
        results["sources"]["ptr"] = ptr_records
    except Exception as e:
        results["sources"]["ptr"] = {"error": str(e)}

    # HackerTarget API (free tier)
    try:
        url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
        req = request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with request.urlopen(req, timeout=15) as response:
            data = response.read().decode()
            if "error" not in data.lower() and "API count" not in data:
                domains = [d.strip() for d in data.split("\n") if d.strip()]
                results["sources"]["hackertarget"] = domains[:50]
    except Exception as e:
        results["sources"]["hackertarget"] = {"error": str(e)}

    return json.dumps(results, indent=2)


@mcp.tool()
async def dns_dumpster(
    domain: str,
) -> str:
    """
    Attempt to gather subdomain information similar to DNSDumpster.
    Uses multiple sources for enumeration.

    Args:
        domain: Domain to enumerate

    Returns:
        Discovered subdomains and DNS information
    """
    results = {
        "domain": domain,
        "subdomains": [],
        "sources_checked": [],
    }

    all_subdomains = set()

    # 1. Certificate Transparency
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        req = request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with request.urlopen(req, timeout=30) as response:
            data = json.loads(response.read().decode())
            for entry in data:
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(domain):
                        all_subdomains.add(name)
        results["sources_checked"].append("crt.sh")
    except Exception:
        pass

    # 2. HackerTarget subdomain finder
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        req = request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with request.urlopen(req, timeout=15) as response:
            data = response.read().decode()
            if "error" not in data.lower():
                for line in data.split("\n"):
                    if "," in line:
                        sub = line.split(",")[0].strip()
                        if sub:
                            all_subdomains.add(sub)
        results["sources_checked"].append("hackertarget")
    except Exception:
        pass

    # 3. ThreatCrowd (if available)
    try:
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
        req = request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read().decode())
            subs = data.get("subdomains", [])
            for sub in subs:
                all_subdomains.add(sub.lower())
        results["sources_checked"].append("threatcrowd")
    except Exception:
        pass

    # 4. DNS brute force common subdomains
    common_subs = ["www", "mail", "ftp", "blog", "dev", "api", "admin", "test", "staging"]
    for sub in common_subs:
        fqdn = f"{sub}.{domain}"
        ips = await _resolve_dns(fqdn, "A")
        if ips:
            all_subdomains.add(fqdn)
    results["sources_checked"].append("dns_bruteforce")

    # Resolve all found subdomains
    for sub in sorted(all_subdomains):
        ips = await _resolve_dns(sub, "A")
        results["subdomains"].append({
            "subdomain": sub,
            "ips": ips if ips else None,
        })

    results["total_found"] = len(results["subdomains"])
    return json.dumps(results, indent=2)


@mcp.tool()
async def get_ssl_certificate(
    host: str,
    port: int = 443,
) -> str:
    """
    Get SSL/TLS certificate information from a host.

    Args:
        host: Hostname to connect to
        port: Port number (default 443)

    Returns:
        Certificate details including subject, issuer, validity, SANs
    """
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                cert_bin = ssock.getpeercert(binary_form=True)

        # If no cert info (due to CERT_NONE), try with verification
        if not cert:
            context2 = ssl.create_default_context()
            try:
                with socket.create_connection((host, port), timeout=10) as sock:
                    with context2.wrap_socket(sock, server_hostname=host) as ssock:
                        cert = ssock.getpeercert()
            except ssl.SSLCertVerificationError:
                pass

        if not cert:
            # Parse binary cert
            import ssl as ssl_module
            cert_pem = ssl_module.DER_cert_to_PEM_cert(cert_bin)
            return json.dumps({
                "host": host,
                "port": port,
                "cert_pem": cert_pem[:500] + "...",
                "note": "Could not parse certificate details",
            }, indent=2)

        # Extract SANs
        sans = []
        for ext in cert.get("subjectAltName", []):
            if ext[0] == "DNS":
                sans.append(ext[1])

        return json.dumps({
            "host": host,
            "port": port,
            "subject": dict(x[0] for x in cert.get("subject", [])),
            "issuer": dict(x[0] for x in cert.get("issuer", [])),
            "version": cert.get("version"),
            "serial_number": cert.get("serialNumber"),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "subject_alt_names": sans,
        }, indent=2)

    except Exception as e:
        return json.dumps({
            "host": host,
            "port": port,
            "error": str(e),
        })


@mcp.tool()
async def subfinder_scan(
    domain: str,
) -> str:
    """
    Run subfinder for subdomain enumeration (if installed).

    Args:
        domain: Domain to enumerate

    Returns:
        Discovered subdomains
    """
    if not _check_tool("subfinder"):
        return json.dumps({
            "error": "subfinder is not installed",
            "install_hint": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        })

    try:
        proc = await asyncio.create_subprocess_exec(
            "subfinder", "-d", domain, "-silent",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)

        subdomains = [
            line.strip()
            for line in stdout.decode().split("\n")
            if line.strip()
        ]

        return json.dumps({
            "domain": domain,
            "tool": "subfinder",
            "count": len(subdomains),
            "subdomains": subdomains,
        }, indent=2)

    except asyncio.TimeoutError:
        return json.dumps({"error": "subfinder timed out"})
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def amass_enum(
    domain: str,
    passive_only: bool = True,
) -> str:
    """
    Run amass for subdomain enumeration (if installed).

    Args:
        domain: Domain to enumerate
        passive_only: Use passive enumeration only (faster, no active probing)

    Returns:
        Discovered subdomains
    """
    if not _check_tool("amass"):
        return json.dumps({
            "error": "amass is not installed",
            "install_hint": "go install -v github.com/owasp-amass/amass/v4/...@master",
        })

    cmd = ["amass", "enum", "-d", domain]
    if passive_only:
        cmd.append("-passive")

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)

        subdomains = [
            line.strip()
            for line in stdout.decode().split("\n")
            if line.strip()
        ]

        return json.dumps({
            "domain": domain,
            "tool": "amass",
            "passive_only": passive_only,
            "count": len(subdomains),
            "subdomains": subdomains,
        }, indent=2)

    except asyncio.TimeoutError:
        return json.dumps({"error": "amass timed out"})
    except Exception as e:
        return json.dumps({"error": str(e)})


if __name__ == "__main__":
    from server_entrypoint import parse_server_args, run_mcp_http_server

    args = parse_server_args(
        description="Subdomain Enumeration MCP Server",
        default_port=8022,
        default_name="recon-subdomain",
    )
    run_mcp_http_server(mcp, args=args)
