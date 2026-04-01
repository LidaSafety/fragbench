#!/usr/bin/env python3
"""
Report Generator MCP Server

Provides security assessment report generation:
- Aggregate findings from multiple scans
- Executive summary generation
- Multiple export formats (Markdown, HTML, JSON)
- Attack chain visualization
- Finding severity classification
- Compliance mapping
"""

import asyncio
import json
import re
from datetime import datetime
from typing import Optional, List, Dict, Any
from pathlib import Path
import html

from fastmcp import FastMCP

mcp = FastMCP("report")

# Store findings in memory for aggregation
FINDINGS_STORE: Dict[str, List[Dict]] = {
    "vulnerabilities": [],
    "recon": [],
    "credentials": [],
    "cloud": [],
    "osint": [],
    "custom": [],
}

# Severity rankings
SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "informational": 4,
    "none": 5,
}

# CVSS to severity mapping
CVSS_SEVERITY = {
    (9.0, 10.0): "critical",
    (7.0, 8.9): "high",
    (4.0, 6.9): "medium",
    (0.1, 3.9): "low",
    (0.0, 0.0): "info",
}


@mcp.tool()
async def add_finding(
    title: str,
    description: str,
    severity: str = "medium",
    category: str = "vulnerabilities",
    target: Optional[str] = None,
    evidence: Optional[str] = None,
    remediation: Optional[str] = None,
    cvss_score: Optional[float] = None,
    cve_id: Optional[str] = None,
    references: Optional[str] = None,
) -> str:
    """
    Add a finding to the report store.

    Args:
        title: Finding title
        description: Detailed description
        severity: Severity level (critical, high, medium, low, info)
        category: Finding category (vulnerabilities, recon, credentials, cloud, osint, custom)
        target: Target affected
        evidence: Evidence/proof of finding
        remediation: Recommended fix
        cvss_score: CVSS score if applicable
        cve_id: CVE identifier if applicable
        references: Comma-separated reference URLs

    Returns:
        JSON confirmation with finding ID
    """
    finding_id = f"F{len(FINDINGS_STORE.get(category, [])) + 1:04d}"

    finding = {
        "id": finding_id,
        "title": title,
        "description": description,
        "severity": severity.lower(),
        "category": category,
        "target": target,
        "evidence": evidence,
        "remediation": remediation,
        "cvss_score": cvss_score,
        "cve_id": cve_id,
        "references": [r.strip() for r in references.split(",")] if references else [],
        "timestamp": datetime.now().isoformat(),
    }

    if category not in FINDINGS_STORE:
        FINDINGS_STORE[category] = []

    FINDINGS_STORE[category].append(finding)

    return json.dumps({
        "status": "added",
        "finding_id": finding_id,
        "category": category,
        "total_findings": sum(len(f) for f in FINDINGS_STORE.values()),
    }, indent=2)


@mcp.tool()
async def import_scan_results(
    scan_output: str,
    scan_type: str,
    target: Optional[str] = None,
) -> str:
    """
    Import findings from scan tool output.

    Args:
        scan_output: JSON output from scan tools
        scan_type: Type of scan (nuclei, nmap, vuln_scanner, cloud_recon, osint)
        target: Override target name

    Returns:
        JSON with import summary
    """
    try:
        data = json.loads(scan_output)
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON input"})

    imported = 0

    if scan_type == "nuclei":
        # Import from nuclei scan results
        vulns = data.get("vulnerabilities", [])
        for vuln in vulns:
            await add_finding(
                title=vuln.get("name", "Unknown"),
                description=vuln.get("description", ""),
                severity=vuln.get("severity", "medium"),
                category="vulnerabilities",
                target=target or data.get("target"),
                evidence=f"Matched at: {vuln.get('matched_at', '')}",
                references=",".join(vuln.get("reference", [])) if vuln.get("reference") else None,
            )
            imported += 1

    elif scan_type == "vuln_scanner":
        # Import from our vuln_scanner results
        vulns = data.get("vulnerabilities", data.get("prioritized", []))
        for vuln in vulns:
            await add_finding(
                title=vuln.get("name") or vuln.get("template_id", "Unknown"),
                description=vuln.get("description", ""),
                severity=vuln.get("severity", "medium"),
                category="vulnerabilities",
                target=target or data.get("target"),
                cvss_score=vuln.get("cvss_score") or vuln.get("cvss_v3", {}).get("score"),
                cve_id=vuln.get("cve_id"),
            )
            imported += 1

    elif scan_type == "cloud_recon":
        # Import cloud findings
        findings = data.get("found", data.get("findings", []))
        for finding in findings:
            severity = "high" if finding.get("public") else "medium"
            await add_finding(
                title=f"Cloud Resource: {finding.get('name', 'Unknown')}",
                description=f"Cloud storage resource discovered: {finding.get('url', '')}",
                severity=severity,
                category="cloud",
                target=target or data.get("target"),
                evidence=json.dumps(finding),
            )
            imported += 1

    elif scan_type == "osint":
        # Import OSINT findings
        for key in ["emails", "usernames", "subdomains"]:
            items = data.get(key, [])
            for item in items[:20]:  # Limit to avoid flooding
                await add_finding(
                    title=f"OSINT: {key.title()} Found",
                    description=f"Discovered {key[:-1]}: {item}",
                    severity="info",
                    category="osint",
                    target=target,
                    evidence=str(item),
                )
                imported += 1

    elif scan_type == "nmap":
        # Import from nmap results
        hosts = data.get("hosts", [data]) if "hosts" in data else [data]
        for host in hosts:
            ports = host.get("ports", host.get("open_ports", []))
            for port in ports:
                port_num = port.get("port") or port.get("portid")
                service = port.get("service", {}).get("name", "unknown")
                await add_finding(
                    title=f"Open Port: {port_num}/{service}",
                    description=f"Service {service} running on port {port_num}",
                    severity="info",
                    category="recon",
                    target=target or host.get("ip") or host.get("host"),
                    evidence=json.dumps(port),
                )
                imported += 1

    return json.dumps({
        "status": "imported",
        "scan_type": scan_type,
        "findings_imported": imported,
        "total_findings": sum(len(f) for f in FINDINGS_STORE.values()),
    }, indent=2)


@mcp.tool()
async def list_findings(
    category: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100,
) -> str:
    """
    List stored findings with optional filters.

    Args:
        category: Filter by category
        severity: Filter by severity
        limit: Maximum findings to return

    Returns:
        JSON with filtered findings
    """
    findings = []

    categories = [category] if category else FINDINGS_STORE.keys()

    for cat in categories:
        for finding in FINDINGS_STORE.get(cat, []):
            if severity and finding.get("severity") != severity.lower():
                continue
            findings.append(finding)

    # Sort by severity
    findings.sort(key=lambda x: SEVERITY_ORDER.get(x.get("severity", "info"), 5))

    return json.dumps({
        "total": len(findings),
        "filters": {"category": category, "severity": severity},
        "findings": findings[:limit],
    }, indent=2)


@mcp.tool()
async def clear_findings(
    category: Optional[str] = None,
) -> str:
    """
    Clear stored findings.

    Args:
        category: Category to clear (all if not specified)

    Returns:
        JSON confirmation
    """
    global FINDINGS_STORE

    if category:
        cleared = len(FINDINGS_STORE.get(category, []))
        FINDINGS_STORE[category] = []
    else:
        cleared = sum(len(f) for f in FINDINGS_STORE.values())
        FINDINGS_STORE = {
            "vulnerabilities": [],
            "recon": [],
            "credentials": [],
            "cloud": [],
            "osint": [],
            "custom": [],
        }

    return json.dumps({
        "status": "cleared",
        "findings_removed": cleared,
        "category": category or "all",
    }, indent=2)


@mcp.tool()
async def generate_executive_summary(
    client_name: str = "Target Organization",
    assessment_type: str = "Security Assessment",
) -> str:
    """
    Generate an executive summary of findings.

    Args:
        client_name: Client/target organization name
        assessment_type: Type of assessment performed

    Returns:
        Executive summary text
    """
    # Collect all findings
    all_findings = []
    for findings in FINDINGS_STORE.values():
        all_findings.extend(findings)

    # Count by severity
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for finding in all_findings:
        sev = finding.get("severity", "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    # Generate summary
    summary = f"""# Executive Summary

## {assessment_type} for {client_name}

**Report Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

### Overview

This report presents the findings from the {assessment_type.lower()} conducted against {client_name}.
The assessment identified a total of **{len(all_findings)} findings** across various severity levels.

### Risk Summary

| Severity | Count | Risk Level |
|----------|-------|------------|
| Critical | {severity_counts['critical']} | Immediate action required |
| High | {severity_counts['high']} | Address within 24-48 hours |
| Medium | {severity_counts['medium']} | Address within 1 week |
| Low | {severity_counts['low']} | Address in maintenance window |
| Informational | {severity_counts['info']} | No immediate action needed |

### Key Findings

"""

    # Add top 5 critical/high findings
    critical_high = [f for f in all_findings if f.get("severity") in ["critical", "high"]]
    critical_high.sort(key=lambda x: SEVERITY_ORDER.get(x.get("severity", "info"), 5))

    for i, finding in enumerate(critical_high[:5], 1):
        summary += f"""
#### {i}. [{finding.get('severity', 'unknown').upper()}] {finding.get('title', 'Unknown')}

{finding.get('description', 'No description provided.')[:200]}

**Target:** {finding.get('target', 'N/A')}
"""

    # Recommendations
    summary += """
### Recommendations

Based on the findings, the following priority actions are recommended:

1. **Immediate (0-24 hours):** Address all critical severity findings
2. **Short-term (1-7 days):** Remediate high severity vulnerabilities
3. **Medium-term (1-4 weeks):** Implement fixes for medium severity issues
4. **Ongoing:** Establish continuous security monitoring and regular assessments

### Conclusion

"""

    if severity_counts["critical"] > 0:
        summary += f"The assessment identified **{severity_counts['critical']} critical** vulnerabilities that require immediate attention. "
    if severity_counts["high"] > 0:
        summary += f"Additionally, **{severity_counts['high']} high** severity issues should be prioritized for remediation. "

    summary += """
We recommend implementing the suggested remediations and conducting a follow-up assessment to verify fixes.

---
*Report generated by Red-APT Security Assessment Framework*
"""

    return summary


@mcp.tool()
async def generate_full_report(
    client_name: str = "Target Organization",
    assessment_type: str = "Security Assessment",
    format: str = "markdown",
    include_evidence: bool = True,
) -> str:
    """
    Generate a comprehensive security assessment report.

    Args:
        client_name: Client/target organization name
        assessment_type: Type of assessment
        format: Output format (markdown, html, json)
        include_evidence: Include evidence in report

    Returns:
        Full assessment report
    """
    # Collect all findings
    all_findings = []
    for findings in FINDINGS_STORE.values():
        all_findings.extend(findings)

    # Sort by severity
    all_findings.sort(key=lambda x: SEVERITY_ORDER.get(x.get("severity", "info"), 5))

    if format == "json":
        return json.dumps({
            "report_metadata": {
                "client": client_name,
                "assessment_type": assessment_type,
                "generated": datetime.now().isoformat(),
                "total_findings": len(all_findings),
            },
            "findings": all_findings,
        }, indent=2)

    # Generate Markdown report
    report = f"""# {assessment_type} Report

## Client: {client_name}

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Framework:** Red-APT Security Assessment

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Methodology](#methodology)
3. [Findings Summary](#findings-summary)
4. [Detailed Findings](#detailed-findings)
5. [Recommendations](#recommendations)
6. [Appendix](#appendix)

---

"""

    # Add executive summary
    exec_summary = await generate_executive_summary(client_name, assessment_type)
    report += exec_summary.replace("# Executive Summary", "## 1. Executive Summary")

    # Methodology
    report += """
---

## 2. Methodology

The assessment was conducted using the Red-APT security framework, which includes:

- **Reconnaissance:** Network scanning, subdomain enumeration, OSINT gathering
- **Vulnerability Assessment:** Automated and manual vulnerability scanning
- **Cloud Security:** Cloud resource enumeration and misconfiguration detection
- **Credential Testing:** Password policy analysis and credential assessment
- **Reporting:** Automated finding aggregation and report generation

### Tools Used

- Network reconnaissance tools (nmap, masscan)
- Web vulnerability scanners (nuclei, nikto)
- Cloud enumeration tools
- OSINT gathering frameworks
- Custom MCP-based automation

---

## 3. Findings Summary

"""

    # Summary table
    categories = {}
    for finding in all_findings:
        cat = finding.get("category", "other")
        if cat not in categories:
            categories[cat] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        sev = finding.get("severity", "info")
        if sev in categories[cat]:
            categories[cat][sev] += 1

    report += "| Category | Critical | High | Medium | Low | Info |\n"
    report += "|----------|----------|------|--------|-----|------|\n"

    for cat, counts in categories.items():
        report += f"| {cat.title()} | {counts['critical']} | {counts['high']} | {counts['medium']} | {counts['low']} | {counts['info']} |\n"

    # Detailed findings
    report += """
---

## 4. Detailed Findings

"""

    for i, finding in enumerate(all_findings, 1):
        severity = finding.get("severity", "unknown").upper()
        severity_badge = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🔵",
            "INFO": "⚪",
        }.get(severity, "⚪")

        report += f"""
### 4.{i}. {severity_badge} [{severity}] {finding.get('title', 'Unknown Finding')}

**ID:** {finding.get('id', 'N/A')}
**Category:** {finding.get('category', 'N/A')}
**Target:** {finding.get('target', 'N/A')}
"""

        if finding.get("cvss_score"):
            report += f"**CVSS Score:** {finding['cvss_score']}\n"

        if finding.get("cve_id"):
            report += f"**CVE:** {finding['cve_id']}\n"

        report += f"""
#### Description

{finding.get('description', 'No description provided.')}

"""

        if include_evidence and finding.get("evidence"):
            report += f"""#### Evidence

```
{finding.get('evidence', '')}
```

"""

        if finding.get("remediation"):
            report += f"""#### Remediation

{finding.get('remediation')}

"""

        if finding.get("references"):
            report += "#### References\n\n"
            for ref in finding.get("references", []):
                report += f"- {ref}\n"

        report += "\n---\n"

    # Recommendations
    report += """
## 5. Recommendations

### Priority Matrix

| Priority | Timeline | Actions |
|----------|----------|---------|
| P1 - Critical | Immediate (0-24h) | Address all critical vulnerabilities |
| P2 - High | Short-term (1-7d) | Remediate high severity issues |
| P3 - Medium | Medium-term (1-4w) | Fix medium severity findings |
| P4 - Low | Long-term (1-3m) | Address low severity items |

### General Recommendations

1. **Vulnerability Management:** Implement regular vulnerability scanning and patching
2. **Access Control:** Review and strengthen access control policies
3. **Monitoring:** Deploy security monitoring and alerting
4. **Incident Response:** Develop/update incident response procedures
5. **Security Training:** Conduct security awareness training

---

## 6. Appendix

### A. Severity Definitions

| Severity | CVSS Range | Description |
|----------|------------|-------------|
| Critical | 9.0 - 10.0 | Exploitation likely leads to full system compromise |
| High | 7.0 - 8.9 | Significant impact, relatively easy to exploit |
| Medium | 4.0 - 6.9 | Moderate impact, requires specific conditions |
| Low | 0.1 - 3.9 | Limited impact, difficult to exploit |
| Info | 0.0 | Informational finding, no direct security impact |

### B. Assessment Scope

This assessment covered the following areas:
- External network reconnaissance
- Web application security
- Cloud infrastructure
- OSINT and information leakage

---

*This report was generated by the Red-APT Security Assessment Framework.*
*For questions or clarifications, contact your security team.*
"""

    if format == "html":
        # Convert Markdown to basic HTML
        return await _markdown_to_html(report)

    return report


async def _markdown_to_html(markdown: str) -> str:
    """Convert markdown to basic HTML."""
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Assessment Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; line-height: 1.6; }}
        h1 {{ color: #1a1a1a; border-bottom: 2px solid #e74c3c; padding-bottom: 10px; }}
        h2 {{ color: #2c3e50; border-bottom: 1px solid #bdc3c7; padding-bottom: 5px; margin-top: 30px; }}
        h3 {{ color: #34495e; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #3498db; color: white; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        code {{ background-color: #f4f4f4; padding: 2px 6px; border-radius: 3px; }}
        pre {{ background-color: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 5px; overflow-x: auto; }}
        .critical {{ color: #e74c3c; font-weight: bold; }}
        .high {{ color: #e67e22; font-weight: bold; }}
        .medium {{ color: #f39c12; font-weight: bold; }}
        .low {{ color: #3498db; }}
        .info {{ color: #95a5a6; }}
        hr {{ border: none; border-top: 1px solid #eee; margin: 30px 0; }}
    </style>
</head>
<body>
"""

    # Basic markdown conversion
    content = html.escape(markdown)

    # Headers
    content = re.sub(r'^### (.+)$', r'<h3>\1</h3>', content, flags=re.MULTILINE)
    content = re.sub(r'^## (.+)$', r'<h2>\1</h2>', content, flags=re.MULTILINE)
    content = re.sub(r'^# (.+)$', r'<h1>\1</h1>', content, flags=re.MULTILINE)

    # Bold and italic
    content = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', content)
    content = re.sub(r'\*(.+?)\*', r'<em>\1</em>', content)

    # Code blocks
    content = re.sub(r'```\n(.+?)\n```', r'<pre><code>\1</code></pre>', content, flags=re.DOTALL)
    content = re.sub(r'`(.+?)`', r'<code>\1</code>', content)

    # Tables (basic)
    lines = content.split('\n')
    in_table = False
    new_lines = []
    for line in lines:
        if '|' in line and not line.startswith('<'):
            if not in_table:
                new_lines.append('<table>')
                in_table = True
            if '---' in line:
                continue
            cells = [c.strip() for c in line.split('|')[1:-1]]
            tag = 'th' if not any('<tr>' in l for l in new_lines[-5:]) else 'td'
            new_lines.append('<tr>' + ''.join(f'<{tag}>{c}</{tag}>' for c in cells) + '</tr>')
        else:
            if in_table:
                new_lines.append('</table>')
                in_table = False
            new_lines.append(line)

    content = '\n'.join(new_lines)

    # Horizontal rules
    content = content.replace('---', '<hr>')

    # Line breaks
    content = re.sub(r'\n\n', '</p><p>', content)
    content = f'<p>{content}</p>'

    html_content += content
    html_content += """
</body>
</html>
"""
    return html_content


@mcp.tool()
async def generate_attack_chain(
    findings_ids: Optional[str] = None,
) -> str:
    """
    Generate an attack chain visualization from findings.

    Args:
        findings_ids: Comma-separated finding IDs to include (all if not specified)

    Returns:
        Attack chain diagram in text/mermaid format
    """
    # Collect findings
    all_findings = []
    for findings in FINDINGS_STORE.values():
        all_findings.extend(findings)

    if findings_ids:
        ids = [f.strip() for f in findings_ids.split(",")]
        all_findings = [f for f in all_findings if f.get("id") in ids]

    if not all_findings:
        return json.dumps({"error": "No findings to chain"})

    # Sort by severity (critical first)
    all_findings.sort(key=lambda x: SEVERITY_ORDER.get(x.get("severity", "info"), 5))

    # Build attack chain
    mermaid = """```mermaid
graph TD
    subgraph Attack Chain
"""

    # Group by category and create nodes
    categories_order = ["recon", "osint", "cloud", "vulnerabilities", "credentials"]

    prev_node = None
    for i, finding in enumerate(all_findings[:10]):  # Limit for readability
        node_id = f"F{i}"
        severity = finding.get("severity", "info").upper()
        title = finding.get("title", "Unknown")[:30]

        # Style based on severity
        style = ""
        if severity == "CRITICAL":
            style = ":::critical"
        elif severity == "HIGH":
            style = ":::high"

        mermaid += f'    {node_id}["{severity}: {title}"]{style}\n'

        if prev_node:
            mermaid += f'    {prev_node} --> {node_id}\n'
        prev_node = node_id

    mermaid += """    end

    classDef critical fill:#e74c3c,color:#fff
    classDef high fill:#e67e22,color:#fff
```

### Attack Narrative

"""

    # Generate narrative
    for i, finding in enumerate(all_findings[:10], 1):
        mermaid += f"{i}. **{finding.get('title', 'Unknown')}** ({finding.get('severity', 'unknown').upper()})\n"
        mermaid += f"   - {finding.get('description', 'No description')[:100]}...\n"
        mermaid += f"   - Target: {finding.get('target', 'N/A')}\n\n"

    return mermaid


@mcp.tool()
async def export_findings(
    format: str = "csv",
    output_file: Optional[str] = None,
) -> str:
    """
    Export findings to various formats.

    Args:
        format: Export format (csv, json, sarif)
        output_file: Optional file path to save (returns content if not specified)

    Returns:
        Exported data or file path
    """
    all_findings = []
    for findings in FINDINGS_STORE.values():
        all_findings.extend(findings)

    if format == "csv":
        lines = ["ID,Title,Severity,Category,Target,CVE,CVSS,Description"]
        for f in all_findings:
            desc = f.get("description", "").replace('"', '""')[:200]
            lines.append(
                f'"{f.get("id", "")}","{f.get("title", "")}","{f.get("severity", "")}","{f.get("category", "")}","{f.get("target", "")}","{f.get("cve_id", "")}","{f.get("cvss_score", "")}","{desc}"'
            )
        content = "\n".join(lines)

    elif format == "json":
        content = json.dumps(all_findings, indent=2)

    elif format == "sarif":
        # SARIF format for GitHub/Azure DevOps integration
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Red-APT",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/redapt",
                    }
                },
                "results": [
                    {
                        "ruleId": f.get("id", ""),
                        "level": {
                            "critical": "error",
                            "high": "error",
                            "medium": "warning",
                            "low": "note",
                            "info": "note",
                        }.get(f.get("severity", "info"), "note"),
                        "message": {"text": f.get("description", "")},
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": f.get("target", "unknown")}
                            }
                        }],
                    }
                    for f in all_findings
                ]
            }]
        }
        content = json.dumps(sarif, indent=2)

    else:
        return json.dumps({"error": f"Unknown format: {format}"})

    if output_file:
        Path(output_file).write_text(content)
        return json.dumps({"status": "exported", "file": output_file, "findings": len(all_findings)})

    return content


@mcp.tool()
async def get_statistics() -> str:
    """
    Get statistics about stored findings.

    Returns:
        JSON with finding statistics
    """
    all_findings = []
    for findings in FINDINGS_STORE.values():
        all_findings.extend(findings)

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    category_counts = {}
    targets = set()

    for finding in all_findings:
        sev = finding.get("severity", "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

        cat = finding.get("category", "other")
        category_counts[cat] = category_counts.get(cat, 0) + 1

        if finding.get("target"):
            targets.add(finding["target"])

    # Calculate risk score
    risk_score = (
        severity_counts["critical"] * 40 +
        severity_counts["high"] * 20 +
        severity_counts["medium"] * 10 +
        severity_counts["low"] * 5
    )

    risk_level = "Low"
    if risk_score >= 100:
        risk_level = "Critical"
    elif risk_score >= 50:
        risk_level = "High"
    elif risk_score >= 20:
        risk_level = "Medium"

    return json.dumps({
        "total_findings": len(all_findings),
        "by_severity": severity_counts,
        "by_category": category_counts,
        "unique_targets": len(targets),
        "targets": list(targets)[:10],
        "risk_score": risk_score,
        "risk_level": risk_level,
        "report_ready": len(all_findings) > 0,
    }, indent=2)


if __name__ == "__main__":
    from fragbench_mcp.servers.server_entrypoint import parse_server_args, run_mcp_http_server

    args = parse_server_args(
        description="Report Generator MCP Server",
        default_port=8030,
        default_name="report",
    )
    run_mcp_http_server(mcp, args=args)
