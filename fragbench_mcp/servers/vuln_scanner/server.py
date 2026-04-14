#!/usr/bin/env python3
"""
Vulnerability Scanner MCP Server

Provides vulnerability assessment capabilities:
- Nuclei template scanning
- CVE database lookups (NVD API)
- Exploit-DB search
- Service-to-CVE correlation
- Vulnerability prioritization
"""

import asyncio
import json
import shutil
import subprocess
import re
from datetime import datetime
from typing import Optional
from pathlib import Path

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "_shared"))

from fastmcp import FastMCP

mcp = FastMCP("vuln_scanner")

# Common vulnerability patterns for service fingerprinting
SERVICE_CVE_MAPPING = {
    "apache": ["CVE-2021-41773", "CVE-2021-42013", "CVE-2023-25690"],
    "nginx": ["CVE-2021-23017", "CVE-2022-41741", "CVE-2023-44487"],
    "openssh": ["CVE-2023-38408", "CVE-2023-48795", "CVE-2024-6387"],
    "mysql": ["CVE-2023-21980", "CVE-2023-22008", "CVE-2024-20960"],
    "postgresql": ["CVE-2023-2454", "CVE-2023-2455", "CVE-2023-39417"],
    "redis": ["CVE-2022-0543", "CVE-2023-28856", "CVE-2023-36824"],
    "tomcat": ["CVE-2023-28708", "CVE-2023-41080", "CVE-2024-23672"],
    "iis": ["CVE-2023-21703", "CVE-2022-30209", "CVE-2022-21907"],
    "wordpress": ["CVE-2023-2745", "CVE-2023-5561", "CVE-2024-27956"],
    "drupal": ["CVE-2022-25277", "CVE-2022-25276", "CVE-2020-13671"],
    "joomla": ["CVE-2023-23752", "CVE-2023-23753", "CVE-2024-21726"],
    "elasticsearch": ["CVE-2023-31419", "CVE-2023-31417", "CVE-2022-23708"],
    "mongodb": ["CVE-2023-1409", "CVE-2021-32040", "CVE-2020-7928"],
    "docker": ["CVE-2024-21626", "CVE-2024-23651", "CVE-2024-23652"],
    "kubernetes": ["CVE-2023-5528", "CVE-2023-3676", "CVE-2022-3294"],
    "jenkins": ["CVE-2024-23897", "CVE-2024-23898", "CVE-2023-27898"],
    "gitlab": ["CVE-2023-7028", "CVE-2023-2825", "CVE-2022-2884"],
    "confluence": ["CVE-2023-22527", "CVE-2023-22515", "CVE-2022-26134"],
    "jira": ["CVE-2022-0540", "CVE-2021-26086", "CVE-2020-36239"],
    "exchange": ["CVE-2023-21529", "CVE-2023-36745", "CVE-2022-41040"],
    "vsftpd": ["CVE-2011-2523"],
    "proftpd": ["CVE-2019-12815", "CVE-2015-3306"],
    "openssl": ["CVE-2022-3602", "CVE-2022-3786", "CVE-2023-0286"],
}

# CVSS severity thresholds
CVSS_SEVERITY = {
    "critical": (9.0, 10.0),
    "high": (7.0, 8.9),
    "medium": (4.0, 6.9),
    "low": (0.1, 3.9),
    "none": (0.0, 0.0),
}


@mcp.tool()
async def nuclei_scan(
    target: str,
    templates: str = "cves,vulnerabilities,exposures",
    severity: str = "critical,high,medium",
    rate_limit: int = 150,
    timeout: int = 300,
) -> str:
    """
    Run Nuclei vulnerability scanner against a target.

    Args:
        target: Target URL or host to scan
        templates: Comma-separated template categories (cves, vulnerabilities, exposures, misconfiguration, default-logins)
        severity: Comma-separated severity levels to include (critical, high, medium, low, info)
        rate_limit: Maximum requests per second
        timeout: Scan timeout in seconds

    Returns:
        JSON with scan results including vulnerabilities found
    """
    if not shutil.which("nuclei"):
        return json.dumps({
            "error": "nuclei not installed",
            "install": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        })

    try:
        cmd = [
            "nuclei",
            "-u", target,
            "-t", templates,
            "-severity", severity,
            "-rate-limit", str(rate_limit),
            "-json",
            "-silent",
        ]

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            process.kill()
            return json.dumps({"error": "Scan timed out", "timeout": timeout})

        vulnerabilities = []
        for line in stdout.decode().strip().split("\n"):
            if line:
                try:
                    vuln = json.loads(line)
                    vulnerabilities.append({
                        "template_id": vuln.get("template-id", ""),
                        "name": vuln.get("info", {}).get("name", ""),
                        "severity": vuln.get("info", {}).get("severity", ""),
                        "matched_at": vuln.get("matched-at", ""),
                        "matcher_name": vuln.get("matcher-name", ""),
                        "description": vuln.get("info", {}).get("description", ""),
                        "reference": vuln.get("info", {}).get("reference", []),
                        "tags": vuln.get("info", {}).get("tags", []),
                    })
                except json.JSONDecodeError:
                    continue

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        vulnerabilities.sort(key=lambda x: severity_order.get(x["severity"], 5))

        return json.dumps({
            "target": target,
            "vulnerabilities_found": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "templates_used": templates,
            "severity_filter": severity,
        }, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def cve_lookup(cve_id: str) -> str:
    """
    Look up CVE details from NVD (National Vulnerability Database).

    Args:
        cve_id: CVE identifier (e.g., CVE-2021-44228)

    Returns:
        JSON with CVE details including description, CVSS score, and references
    """
    import urllib.request
    import urllib.error

    # Validate CVE format
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id.upper()):
        return json.dumps({"error": "Invalid CVE format. Use CVE-YYYY-NNNNN"})

    cve_id = cve_id.upper()

    try:
        # NVD API 2.0
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"

        req = urllib.request.Request(url, headers={"User-Agent": "Red-APT-Scanner/1.0"})

        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None, lambda: urllib.request.urlopen(req, timeout=30)
        )
        data = json.loads(response.read().decode())

        if not data.get("vulnerabilities"):
            return json.dumps({"error": f"CVE {cve_id} not found"})

        cve_data = data["vulnerabilities"][0]["cve"]

        # Extract CVSS scores
        cvss_v3 = None
        cvss_v2 = None

        metrics = cve_data.get("metrics", {})
        if "cvssMetricV31" in metrics:
            cvss_v3 = metrics["cvssMetricV31"][0]["cvssData"]
        elif "cvssMetricV30" in metrics:
            cvss_v3 = metrics["cvssMetricV30"][0]["cvssData"]
        if "cvssMetricV2" in metrics:
            cvss_v2 = metrics["cvssMetricV2"][0]["cvssData"]

        # Get description
        descriptions = cve_data.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d["lang"] == "en"),
            descriptions[0]["value"] if descriptions else "No description"
        )

        # Get references
        references = [
            {"url": ref["url"], "source": ref.get("source", "")}
            for ref in cve_data.get("references", [])[:10]
        ]

        # Determine severity
        base_score = None
        severity = "unknown"
        if cvss_v3:
            base_score = cvss_v3.get("baseScore")
            severity = cvss_v3.get("baseSeverity", "").lower()
        elif cvss_v2:
            base_score = cvss_v2.get("baseScore")
            if base_score:
                if base_score >= 9.0:
                    severity = "critical"
                elif base_score >= 7.0:
                    severity = "high"
                elif base_score >= 4.0:
                    severity = "medium"
                else:
                    severity = "low"

        return json.dumps({
            "cve_id": cve_id,
            "description": description,
            "severity": severity,
            "cvss_v3": {
                "score": cvss_v3.get("baseScore") if cvss_v3 else None,
                "vector": cvss_v3.get("vectorString") if cvss_v3 else None,
                "severity": cvss_v3.get("baseSeverity") if cvss_v3 else None,
            },
            "cvss_v2": {
                "score": cvss_v2.get("baseScore") if cvss_v2 else None,
                "vector": cvss_v2.get("vectorString") if cvss_v2 else None,
            },
            "published": cve_data.get("published", ""),
            "modified": cve_data.get("lastModified", ""),
            "references": references,
            "weaknesses": [
                w["description"][0]["value"]
                for w in cve_data.get("weaknesses", [])
                if w.get("description")
            ],
        }, indent=2)

    except urllib.error.HTTPError as e:
        return json.dumps({"error": f"HTTP error: {e.code}", "cve_id": cve_id})
    except Exception as e:
        return json.dumps({"error": str(e), "cve_id": cve_id})


@mcp.tool()
async def search_cves(
    keyword: str,
    severity: Optional[str] = None,
    year: Optional[int] = None,
    limit: int = 20,
) -> str:
    """
    Search CVEs by keyword, severity, or year.

    Args:
        keyword: Search keyword (product name, technology, etc.)
        severity: Filter by severity (critical, high, medium, low)
        year: Filter by CVE year
        limit: Maximum results to return

    Returns:
        JSON with matching CVEs
    """
    import urllib.request
    import urllib.parse
    import urllib.error

    try:
        params = {"keywordSearch": keyword, "resultsPerPage": min(limit, 50)}

        if year:
            params["pubStartDate"] = f"{year}-01-01T00:00:00.000"
            params["pubEndDate"] = f"{year}-12-31T23:59:59.999"

        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{urllib.parse.urlencode(params)}"

        req = urllib.request.Request(url, headers={"User-Agent": "Red-APT-Scanner/1.0"})

        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None, lambda: urllib.request.urlopen(req, timeout=30)
        )
        data = json.loads(response.read().decode())

        results = []
        for vuln in data.get("vulnerabilities", []):
            cve = vuln["cve"]

            # Get CVSS score
            metrics = cve.get("metrics", {})
            cvss_score = None
            cve_severity = "unknown"

            if "cvssMetricV31" in metrics:
                cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                cve_severity = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"].lower()
            elif "cvssMetricV30" in metrics:
                cvss_score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
                cve_severity = metrics["cvssMetricV30"][0]["cvssData"]["baseSeverity"].lower()
            elif "cvssMetricV2" in metrics:
                cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

            # Apply severity filter
            if severity and cve_severity != severity.lower():
                continue

            descriptions = cve.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d["lang"] == "en"),
                descriptions[0]["value"] if descriptions else ""
            )

            results.append({
                "cve_id": cve["id"],
                "description": description[:300] + "..." if len(description) > 300 else description,
                "cvss_score": cvss_score,
                "severity": cve_severity,
                "published": cve.get("published", ""),
            })

        # Sort by CVSS score descending
        results.sort(key=lambda x: x["cvss_score"] or 0, reverse=True)

        return json.dumps({
            "keyword": keyword,
            "total_results": data.get("totalResults", 0),
            "returned": len(results),
            "cves": results[:limit],
        }, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def exploit_db_search(
    query: str,
    exploit_type: str = "all",
    platform: str = "all",
    limit: int = 20,
) -> str:
    """
    Search Exploit-DB for public exploits.

    Args:
        query: Search query (CVE, product name, etc.)
        exploit_type: Type filter (all, webapps, remote, local, dos, shellcode)
        platform: Platform filter (all, linux, windows, multiple, hardware)
        limit: Maximum results to return

    Returns:
        JSON with matching exploits from Exploit-DB
    """
    # Check if searchsploit is available
    if shutil.which("searchsploit"):
        return await _searchsploit_search(query, exploit_type, limit)

    # Fallback to web scraping approach
    import urllib.request
    import urllib.parse
    import urllib.error

    try:
        # Build search URL
        base_url = "https://www.exploit-db.com/search"
        params = {"q": query}

        if exploit_type != "all":
            type_map = {
                "webapps": "1",
                "remote": "2",
                "local": "3",
                "dos": "4",
                "shellcode": "5",
            }
            if exploit_type in type_map:
                params["type"] = type_map[exploit_type]

        # Note: Exploit-DB requires proper headers and may block scrapers
        # This provides guidance on manual searching
        return json.dumps({
            "query": query,
            "search_url": f"https://www.exploit-db.com/search?q={urllib.parse.quote(query)}",
            "searchsploit_command": f"searchsploit {query}",
            "note": "Install searchsploit for offline exploit database: apt install exploitdb",
            "alternative_sources": [
                f"https://cvedetails.com/cve-search.php?q={urllib.parse.quote(query)}",
                f"https://vulners.com/search?query={urllib.parse.quote(query)}",
                f"https://packetstormsecurity.com/search/?q={urllib.parse.quote(query)}",
            ],
        }, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e)})


async def _searchsploit_search(query: str, exploit_type: str, limit: int) -> str:
    """Use local searchsploit for exploit search."""
    try:
        cmd = ["searchsploit", "--json", query]

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=60)
        data = json.loads(stdout.decode())

        exploits = []
        for exp in data.get("RESULTS_EXPLOIT", [])[:limit]:
            exploits.append({
                "title": exp.get("Title", ""),
                "edb_id": exp.get("EDB-ID", ""),
                "date": exp.get("Date", ""),
                "author": exp.get("Author", ""),
                "platform": exp.get("Platform", ""),
                "type": exp.get("Type", ""),
                "path": exp.get("Path", ""),
            })

        return json.dumps({
            "query": query,
            "total_found": len(data.get("RESULTS_EXPLOIT", [])),
            "exploits": exploits,
            "source": "searchsploit (local)",
        }, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def service_to_cves(
    service: str,
    version: Optional[str] = None,
) -> str:
    """
    Map a service/product to known CVEs.

    Args:
        service: Service or product name (e.g., apache, nginx, openssh)
        version: Optional version string for more specific matches

    Returns:
        JSON with associated CVEs and recommended checks
    """
    service_lower = service.lower()

    # Find matching service
    matched_service = None
    for svc in SERVICE_CVE_MAPPING:
        if svc in service_lower or service_lower in svc:
            matched_service = svc
            break

    if not matched_service:
        # Try to search NVD for this service
        return json.dumps({
            "service": service,
            "version": version,
            "known_cves": [],
            "recommendation": f"No pre-mapped CVEs. Use search_cves('{service}') for dynamic lookup",
            "nuclei_command": f"nuclei -u TARGET -t cves/ -tags {service}",
        }, indent=2)

    cves = SERVICE_CVE_MAPPING[matched_service]

    # Get details for each CVE
    cve_details = []
    for cve_id in cves[:5]:  # Limit to avoid rate limiting
        try:
            result = await cve_lookup(cve_id)
            data = json.loads(result)
            if "error" not in data:
                cve_details.append({
                    "cve_id": data["cve_id"],
                    "severity": data["severity"],
                    "cvss_score": data.get("cvss_v3", {}).get("score"),
                    "description": data["description"][:200] + "...",
                })
        except Exception:
            cve_details.append({"cve_id": cve_id, "error": "Failed to fetch details"})

        # Small delay to avoid rate limiting
        await asyncio.sleep(0.5)

    return json.dumps({
        "service": service,
        "matched_service": matched_service,
        "version": version,
        "known_cves": cve_details,
        "total_mapped_cves": len(cves),
        "nuclei_templates": [
            f"nuclei -t cves/ -tags {matched_service}",
            f"nuclei -t vulnerabilities/ -tags {matched_service}",
        ],
        "recommendation": "Run nuclei_scan() with these templates for automated detection",
    }, indent=2)


@mcp.tool()
async def vulnerability_prioritize(
    vulnerabilities: str,
) -> str:
    """
    Prioritize a list of vulnerabilities by severity and exploitability.

    Args:
        vulnerabilities: JSON string of vulnerabilities with cvss_score and/or severity

    Returns:
        JSON with prioritized vulnerabilities and remediation order
    """
    try:
        vulns = json.loads(vulnerabilities)
        if not isinstance(vulns, list):
            vulns = [vulns]

        scored_vulns = []
        for vuln in vulns:
            score = 0

            # Base score from CVSS
            cvss = vuln.get("cvss_score") or vuln.get("cvss_v3", {}).get("score") or 0
            score += cvss * 10

            # Severity bonus
            severity = (vuln.get("severity") or "").lower()
            severity_bonus = {
                "critical": 50,
                "high": 30,
                "medium": 15,
                "low": 5,
            }
            score += severity_bonus.get(severity, 0)

            # Exploitability bonus (if known exploit exists)
            if vuln.get("exploit_available") or "exploit" in str(vuln).lower():
                score += 40

            # Network accessible bonus
            if vuln.get("network_accessible") or "remote" in str(vuln).lower():
                score += 20

            scored_vulns.append({
                **vuln,
                "priority_score": score,
            })

        # Sort by priority score descending
        scored_vulns.sort(key=lambda x: x["priority_score"], reverse=True)

        # Assign priority levels
        for i, vuln in enumerate(scored_vulns):
            if vuln["priority_score"] >= 100:
                vuln["priority"] = "P1 - Critical"
                vuln["remediation"] = "Immediate action required"
            elif vuln["priority_score"] >= 70:
                vuln["priority"] = "P2 - High"
                vuln["remediation"] = "Address within 24-48 hours"
            elif vuln["priority_score"] >= 40:
                vuln["priority"] = "P3 - Medium"
                vuln["remediation"] = "Address within 1 week"
            else:
                vuln["priority"] = "P4 - Low"
                vuln["remediation"] = "Address in next maintenance window"

        return json.dumps({
            "total_vulnerabilities": len(scored_vulns),
            "critical_count": sum(1 for v in scored_vulns if "P1" in v.get("priority", "")),
            "high_count": sum(1 for v in scored_vulns if "P2" in v.get("priority", "")),
            "medium_count": sum(1 for v in scored_vulns if "P3" in v.get("priority", "")),
            "low_count": sum(1 for v in scored_vulns if "P4" in v.get("priority", "")),
            "prioritized": scored_vulns,
        }, indent=2)

    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON input"})
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def nikto_scan(
    target: str,
    port: int = 80,
    ssl: bool = False,
    timeout: int = 300,
) -> str:
    """
    Run Nikto web vulnerability scanner.

    Args:
        target: Target URL or host
        port: Target port
        ssl: Use SSL/TLS
        timeout: Scan timeout in seconds

    Returns:
        JSON with Nikto scan results
    """
    if not shutil.which("nikto"):
        return json.dumps({
            "error": "nikto not installed",
            "install": "apt install nikto",
        })

    try:
        cmd = ["nikto", "-h", target, "-p", str(port), "-Format", "json", "-o", "-"]
        if ssl:
            cmd.extend(["-ssl"])

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            process.kill()
            return json.dumps({"error": "Scan timed out", "timeout": timeout})

        output = stdout.decode()

        # Parse Nikto output
        vulnerabilities = []
        for line in output.split("\n"):
            if "+ " in line and ":" in line:
                vulnerabilities.append(line.strip())

        return json.dumps({
            "target": target,
            "port": port,
            "ssl": ssl,
            "findings_count": len(vulnerabilities),
            "findings": vulnerabilities[:50],
            "raw_output": output[:5000] if len(output) > 5000 else output,
        }, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def wpscan(
    target: str,
    enumerate: str = "vp,vt,u",
    api_token: Optional[str] = None,
    timeout: int = 300,
) -> str:
    """
    Run WPScan for WordPress vulnerability scanning.

    Args:
        target: Target WordPress URL
        enumerate: Enumeration options (vp=plugins, vt=themes, u=users, ap=all plugins)
        api_token: WPScan API token for vulnerability data
        timeout: Scan timeout in seconds

    Returns:
        JSON with WordPress vulnerabilities and findings
    """
    if not shutil.which("wpscan"):
        return json.dumps({
            "error": "wpscan not installed",
            "install": "gem install wpscan",
        })

    try:
        cmd = [
            "wpscan",
            "--url", target,
            "--enumerate", enumerate,
            "--format", "json",
            "--no-banner",
        ]

        if api_token:
            cmd.extend(["--api-token", api_token])

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            process.kill()
            return json.dumps({"error": "Scan timed out", "timeout": timeout})

        try:
            results = json.loads(stdout.decode())
            return json.dumps({
                "target": target,
                "wordpress_version": results.get("version", {}).get("number"),
                "interesting_findings": results.get("interesting_findings", []),
                "plugins": results.get("plugins", {}),
                "themes": results.get("themes", {}),
                "users": results.get("users", []),
                "vulnerabilities": results.get("vulnerabilities", []),
            }, indent=2)
        except json.JSONDecodeError:
            return json.dumps({
                "target": target,
                "raw_output": stdout.decode()[:5000],
            })

    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def ssl_scan(
    target: str,
    port: int = 443,
    timeout: int = 60,
) -> str:
    """
    Scan SSL/TLS configuration for vulnerabilities.

    Args:
        target: Target hostname
        port: Target port
        timeout: Scan timeout in seconds

    Returns:
        JSON with SSL/TLS vulnerabilities and configuration issues
    """
    import ssl
    import socket

    results = {
        "target": target,
        "port": port,
        "vulnerabilities": [],
        "certificate": {},
        "protocols": {},
        "ciphers": [],
    }

    try:
        # Test different TLS versions
        protocols = {
            "TLSv1.0": ssl.TLSVersion.TLSv1,
            "TLSv1.1": ssl.TLSVersion.TLSv1_1,
            "TLSv1.2": ssl.TLSVersion.TLSv1_2,
            "TLSv1.3": ssl.TLSVersion.TLSv1_3,
        }

        for proto_name, proto_version in protocols.items():
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.minimum_version = proto_version
                context.maximum_version = proto_version
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                with socket.create_connection((target, port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=target) as ssock:
                        results["protocols"][proto_name] = "supported"

                        if proto_name in ["TLSv1.0", "TLSv1.1"]:
                            results["vulnerabilities"].append({
                                "finding": f"Deprecated {proto_name} supported",
                                "severity": "medium",
                                "recommendation": f"Disable {proto_name}",
                            })
            except Exception:
                results["protocols"][proto_name] = "not supported"

        # Get certificate details
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((target, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if cert:
                    results["certificate"] = {
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter"),
                        "serial": cert.get("serialNumber"),
                    }

                # Check cipher
                cipher = ssock.cipher()
                if cipher:
                    results["current_cipher"] = {
                        "name": cipher[0],
                        "protocol": cipher[1],
                        "bits": cipher[2],
                    }

                    # Check for weak ciphers
                    weak_ciphers = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT"]
                    if any(weak in cipher[0] for weak in weak_ciphers):
                        results["vulnerabilities"].append({
                            "finding": f"Weak cipher in use: {cipher[0]}",
                            "severity": "high",
                            "recommendation": "Disable weak ciphers",
                        })

        # Summary
        results["summary"] = {
            "total_vulnerabilities": len(results["vulnerabilities"]),
            "deprecated_protocols": sum(
                1 for p in ["TLSv1.0", "TLSv1.1"]
                if results["protocols"].get(p) == "supported"
            ),
        }

        return json.dumps(results, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e), "target": target})


@mcp.tool()
async def generate_vuln_report(
    scan_results: str,
    format: str = "markdown",
) -> str:
    """
    Generate a vulnerability report from scan results.

    Args:
        scan_results: JSON string of scan results
        format: Output format (markdown, json, text)

    Returns:
        Formatted vulnerability report
    """
    try:
        results = json.loads(scan_results)

        if format == "json":
            return json.dumps(results, indent=2)

        report_lines = []

        if format == "markdown":
            report_lines.append("# Vulnerability Scan Report")
            report_lines.append(f"\n**Generated:** {datetime.now().isoformat()}")

            if "target" in results:
                report_lines.append(f"\n**Target:** {results['target']}")

            report_lines.append("\n## Executive Summary\n")

            vuln_count = results.get("vulnerabilities_found") or len(results.get("vulnerabilities", []))
            report_lines.append(f"- Total vulnerabilities found: **{vuln_count}**")

            vulns = results.get("vulnerabilities", [])
            if vulns:
                critical = sum(1 for v in vulns if v.get("severity", "").lower() == "critical")
                high = sum(1 for v in vulns if v.get("severity", "").lower() == "high")
                medium = sum(1 for v in vulns if v.get("severity", "").lower() == "medium")

                report_lines.append(f"- Critical: **{critical}**")
                report_lines.append(f"- High: **{high}**")
                report_lines.append(f"- Medium: **{medium}**")

                report_lines.append("\n## Detailed Findings\n")

                for i, vuln in enumerate(vulns, 1):
                    severity = vuln.get("severity", "unknown").upper()
                    name = vuln.get("name") or vuln.get("template_id", "Unknown")
                    report_lines.append(f"### {i}. [{severity}] {name}\n")

                    if vuln.get("description"):
                        report_lines.append(f"**Description:** {vuln['description']}\n")
                    if vuln.get("matched_at"):
                        report_lines.append(f"**Location:** {vuln['matched_at']}\n")
                    if vuln.get("reference"):
                        refs = vuln["reference"]
                        if isinstance(refs, list):
                            report_lines.append("**References:**")
                            for ref in refs[:3]:
                                report_lines.append(f"- {ref}")
                    report_lines.append("")

            report_lines.append("\n## Recommendations\n")
            report_lines.append("1. Address critical and high severity vulnerabilities immediately")
            report_lines.append("2. Schedule medium severity fixes within the next sprint")
            report_lines.append("3. Review and update security policies")
            report_lines.append("4. Re-scan after remediation to verify fixes")

        else:  # text format
            report_lines.append("=" * 60)
            report_lines.append("VULNERABILITY SCAN REPORT")
            report_lines.append("=" * 60)
            report_lines.append(f"Generated: {datetime.now().isoformat()}")

            if "target" in results:
                report_lines.append(f"Target: {results['target']}")

            vulns = results.get("vulnerabilities", [])
            report_lines.append(f"\nTotal Findings: {len(vulns)}")
            report_lines.append("-" * 60)

            for i, vuln in enumerate(vulns, 1):
                report_lines.append(f"\n[{i}] {vuln.get('severity', 'UNKNOWN').upper()}: {vuln.get('name', 'Unknown')}")
                if vuln.get("description"):
                    report_lines.append(f"    {vuln['description'][:100]}...")

        return "\n".join(report_lines)

    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON input"})
    except Exception as e:
        return json.dumps({"error": str(e)})


if __name__ == "__main__":
    from server_entrypoint import parse_server_args, run_mcp_http_server

    args = parse_server_args(
        description="Vulnerability Scanner MCP Server",
        default_port=8034,
        default_name="vuln_scanner",
    )
    run_mcp_http_server(mcp, args=args)
