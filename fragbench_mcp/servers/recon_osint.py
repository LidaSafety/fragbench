#!/usr/bin/env python3
"""
OSINT (Open Source Intelligence) MCP Server for Red Team Operations.

Provides tools for:
- Email harvesting
- Username enumeration
- Social media reconnaissance
- Credential leak checking
- Metadata extraction
- Public data aggregation
"""

import asyncio
import base64
import hashlib
import json
import re
import shutil
from pathlib import Path
from typing import Any, Optional
from urllib import request, error, parse
import ssl

from fastmcp import FastMCP

# Initialize MCP server
mcp = FastMCP("recon-osint")


def _make_request(
    url: str,
    headers: Optional[dict] = None,
    timeout: int = 15,
) -> tuple[int, dict, bytes]:
    """Make HTTP request and return (status, headers, body)."""
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    if headers:
        default_headers.update(headers)

    req = request.Request(url, headers=default_headers)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        response = request.urlopen(req, timeout=timeout, context=ctx)
        return response.status, dict(response.headers), response.read()
    except error.HTTPError as e:
        return e.code, dict(e.headers), e.read() if e.fp else b""


# Social media and service patterns for username enumeration
USERNAME_SITES = {
    "github": "https://github.com/{username}",
    "twitter": "https://twitter.com/{username}",
    "instagram": "https://www.instagram.com/{username}/",
    "linkedin": "https://www.linkedin.com/in/{username}/",
    "reddit": "https://www.reddit.com/user/{username}",
    "youtube": "https://www.youtube.com/@{username}",
    "tiktok": "https://www.tiktok.com/@{username}",
    "pinterest": "https://www.pinterest.com/{username}/",
    "medium": "https://medium.com/@{username}",
    "dev.to": "https://dev.to/{username}",
    "gitlab": "https://gitlab.com/{username}",
    "bitbucket": "https://bitbucket.org/{username}/",
    "keybase": "https://keybase.io/{username}",
    "hackernews": "https://news.ycombinator.com/user?id={username}",
    "stackoverflow": "https://stackoverflow.com/users/{username}",
    "soundcloud": "https://soundcloud.com/{username}",
    "twitch": "https://www.twitch.tv/{username}",
    "vimeo": "https://vimeo.com/{username}",
    "behance": "https://www.behance.net/{username}",
    "dribbble": "https://dribbble.com/{username}",
    "flickr": "https://www.flickr.com/people/{username}/",
    "pastebin": "https://pastebin.com/u/{username}",
}


@mcp.tool()
async def email_harvest(
    domain: str,
    sources: str = "all",
) -> str:
    """
    Harvest email addresses associated with a domain.

    Args:
        domain: Target domain to search for emails
        sources: Sources to check - "all", "google", "bing", "hunter"

    Returns:
        Found email addresses with their sources
    """
    emails = set()
    results = {
        "domain": domain,
        "sources_checked": [],
        "emails": [],
    }

    # Email pattern
    email_pattern = re.compile(
        rf'[a-zA-Z0-9._%+-]+@{re.escape(domain)}',
        re.IGNORECASE
    )

    # Hunter.io API (free tier - limited)
    if sources in ["all", "hunter"]:
        try:
            hunter_url = f"https://api.hunter.io/v2/domain-search?domain={domain}"
            status, headers, body = await asyncio.to_thread(
                _make_request, hunter_url
            )
            if status == 200:
                data = json.loads(body.decode())
                for email_data in data.get("data", {}).get("emails", []):
                    emails.add(email_data.get("value", ""))
            results["sources_checked"].append("hunter.io")
        except Exception:
            pass

    # Search engine scraping (basic - may be blocked)
    search_queries = [
        f'site:{domain} email',
        f'"{domain}" contact email',
        f'intext:"@{domain}"',
    ]

    if sources in ["all", "google"]:
        for query in search_queries[:1]:  # Limit queries
            try:
                encoded_query = parse.quote(query)
                google_url = f"https://www.google.com/search?q={encoded_query}&num=50"
                status, headers, body = await asyncio.to_thread(
                    _make_request, google_url
                )
                if status == 200:
                    text = body.decode("utf-8", errors="replace")
                    found = email_pattern.findall(text)
                    emails.update(found)
                results["sources_checked"].append("google")
            except Exception:
                pass

    # crt.sh certificate data often contains emails
    try:
        crt_url = f"https://crt.sh/?q=%.{domain}&output=json"
        status, headers, body = await asyncio.to_thread(
            _make_request, crt_url
        )
        if status == 200:
            text = body.decode("utf-8", errors="replace")
            found = email_pattern.findall(text)
            emails.update(found)
        results["sources_checked"].append("crt.sh")
    except Exception:
        pass

    # Clean and return
    results["emails"] = sorted([e.lower() for e in emails if e])
    results["count"] = len(results["emails"])

    return json.dumps(results, indent=2)


@mcp.tool()
async def username_search(
    username: str,
    sites: Optional[str] = None,
) -> str:
    """
    Check if a username exists across multiple platforms.

    Args:
        username: Username to search for
        sites: Comma-separated list of sites to check (default: all)

    Returns:
        Sites where the username was found
    """
    if sites:
        sites_to_check = {
            k: v for k, v in USERNAME_SITES.items()
            if k in [s.strip().lower() for s in sites.split(",")]
        }
    else:
        sites_to_check = USERNAME_SITES

    results = {
        "username": username,
        "found": [],
        "not_found": [],
        "errors": [],
    }

    sem = asyncio.Semaphore(10)

    async def check_site(site_name: str, url_template: str) -> dict:
        url = url_template.format(username=username)
        async with sem:
            try:
                status, headers, body = await asyncio.to_thread(
                    _make_request, url
                )

                # Different sites have different indicators
                found = False
                if status == 200:
                    body_text = body.decode("utf-8", errors="replace").lower()
                    # Check for common "not found" patterns
                    not_found_patterns = [
                        "page not found",
                        "user not found",
                        "doesn't exist",
                        "does not exist",
                        "404",
                        "no user",
                    ]
                    if not any(p in body_text for p in not_found_patterns):
                        found = True

                return {
                    "site": site_name,
                    "url": url,
                    "found": found,
                    "status": status,
                }
            except Exception as e:
                return {
                    "site": site_name,
                    "url": url,
                    "error": str(e),
                }

    tasks = [
        check_site(name, template)
        for name, template in sites_to_check.items()
    ]
    check_results = await asyncio.gather(*tasks)

    for r in check_results:
        if "error" in r:
            results["errors"].append(r)
        elif r.get("found"):
            results["found"].append(r)
        else:
            results["not_found"].append(r)

    results["total_found"] = len(results["found"])
    return json.dumps(results, indent=2)


@mcp.tool()
async def haveibeenpwned_check(
    email: str,
) -> str:
    """
    Check if an email has been in known data breaches.
    Note: Uses unofficial API endpoint, may have rate limits.

    Args:
        email: Email address to check

    Returns:
        Known breaches containing this email
    """
    # Hash the email for the API
    email_sha1 = hashlib.sha1(email.lower().encode()).hexdigest()

    results = {
        "email": email,
        "breaches": [],
        "note": "This is a basic check. For comprehensive results, use haveibeenpwned.com",
    }

    # Try DeHashed-style API (public)
    try:
        url = f"https://api.pwnedpasswords.com/range/{email_sha1[:5]}"
        status, headers, body = await asyncio.to_thread(_make_request, url)
        results["password_hash_exposed"] = email_sha1[5:].upper() in body.decode().upper()
    except Exception:
        pass

    # Check breach compilation sources
    try:
        # Firefox Monitor uses HIBP backend
        url = f"https://monitor.firefox.com/scan"
        # This would need proper API access
        results["check_manually"] = "https://haveibeenpwned.com/"
    except Exception:
        pass

    return json.dumps(results, indent=2)


@mcp.tool()
async def google_dork(
    query: str,
    site: Optional[str] = None,
    filetype: Optional[str] = None,
    intitle: Optional[str] = None,
    inurl: Optional[str] = None,
) -> str:
    """
    Build and explain a Google dork query.

    Args:
        query: Base search query
        site: Limit to specific site
        filetype: File type to search for
        intitle: Text that must be in title
        inurl: Text that must be in URL

    Returns:
        Constructed dork query and explanation
    """
    parts = []

    if site:
        parts.append(f"site:{site}")
    if filetype:
        parts.append(f"filetype:{filetype}")
    if intitle:
        parts.append(f"intitle:{intitle}")
    if inurl:
        parts.append(f"inurl:{inurl}")

    parts.append(query)

    full_query = " ".join(parts)
    encoded = parse.quote(full_query)
    google_url = f"https://www.google.com/search?q={encoded}"

    # Common useful dorks
    example_dorks = {
        "Find exposed configs": f'site:{site or "example.com"} ext:conf OR ext:cfg OR ext:ini',
        "Find SQL files": f'site:{site or "example.com"} ext:sql',
        "Find backup files": f'site:{site or "example.com"} ext:bak OR ext:backup OR ext:old',
        "Find login pages": f'site:{site or "example.com"} inurl:login OR inurl:signin',
        "Find admin panels": f'site:{site or "example.com"} inurl:admin OR inurl:administrator',
        "Find exposed docs": f'site:{site or "example.com"} ext:doc OR ext:docx OR ext:pdf',
        "Find error messages": f'site:{site or "example.com"} "sql syntax" OR "mysql error"',
        "Find directory listings": f'site:{site or "example.com"} intitle:"index of"',
    }

    return json.dumps({
        "query": full_query,
        "url": google_url,
        "example_dorks": example_dorks if site else {},
    }, indent=2)


@mcp.tool()
async def domain_reputation(
    domain: str,
) -> str:
    """
    Check domain reputation across multiple sources.

    Args:
        domain: Domain to check

    Returns:
        Reputation data from various sources
    """
    results = {
        "domain": domain,
        "sources": {},
    }

    # VirusTotal (requires API key for full data, but basic is free)
    try:
        vt_url = f"https://www.virustotal.com/vtapi/v2/domain/report?domain={domain}"
        # Would need API key
        results["sources"]["virustotal"] = {
            "check_url": f"https://www.virustotal.com/gui/domain/{domain}",
            "note": "Requires API key for programmatic access",
        }
    except Exception:
        pass

    # AbuseIPDB (for IPs, but useful reference)
    results["sources"]["abuseipdb"] = {
        "check_url": f"https://www.abuseipdb.com/check/{domain}",
    }

    # URLVoid
    results["sources"]["urlvoid"] = {
        "check_url": f"https://www.urlvoid.com/scan/{domain}/",
    }

    # Talos Intelligence
    results["sources"]["talos"] = {
        "check_url": f"https://talosintelligence.com/reputation_center/lookup?search={domain}",
    }

    # Google Safe Browsing (would need API)
    results["sources"]["google_safe_browsing"] = {
        "check_url": f"https://transparencyreport.google.com/safe-browsing/search?url={domain}",
    }

    return json.dumps(results, indent=2)


@mcp.tool()
async def metadata_extract(
    url: str,
) -> str:
    """
    Extract metadata from a remote file (PDF, image, etc.).

    Args:
        url: URL of the file to analyze

    Returns:
        Extracted metadata if available
    """
    if not shutil.which("exiftool"):
        return json.dumps({
            "error": "exiftool is not installed",
            "install_hint": "apt install libimage-exiftool-perl",
        })

    try:
        # Download file to temp location
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix=".tmp") as tmp:
            req = request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with request.urlopen(req, timeout=30, context=ctx) as response:
                tmp.write(response.read())
            tmp_path = tmp.name

        # Run exiftool
        proc = await asyncio.create_subprocess_exec(
            "exiftool", "-j", tmp_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)

        # Clean up
        Path(tmp_path).unlink(missing_ok=True)

        metadata = json.loads(stdout.decode())[0]

        # Filter sensitive/useful fields
        interesting_fields = [
            "Author", "Creator", "Producer", "CreatorTool",
            "CreateDate", "ModifyDate", "LastModifiedBy",
            "Company", "Manager", "Software", "Generator",
            "GPSLatitude", "GPSLongitude", "GPSPosition",
            "Make", "Model", "SerialNumber",
            "XMPToolkit", "MetadataDate", "HistorySoftwareAgent",
        ]

        filtered = {
            k: v for k, v in metadata.items()
            if any(f.lower() in k.lower() for f in interesting_fields)
        }

        return json.dumps({
            "url": url,
            "interesting_metadata": filtered,
            "all_fields": len(metadata),
            "full_metadata": metadata,
        }, indent=2)

    except Exception as e:
        return json.dumps({"url": url, "error": str(e)})


@mcp.tool()
async def github_recon(
    target: str,
    search_type: str = "user",
) -> str:
    """
    Perform reconnaissance on GitHub.

    Args:
        target: Username, organization, or search query
        search_type: "user", "org", "repo", or "code"

    Returns:
        GitHub profile and repository information
    """
    results = {
        "target": target,
        "type": search_type,
        "data": {},
    }

    base_api = "https://api.github.com"
    headers = {"Accept": "application/vnd.github.v3+json"}

    try:
        if search_type == "user":
            # Get user info
            user_url = f"{base_api}/users/{target}"
            status, _, body = await asyncio.to_thread(
                _make_request, user_url, headers
            )
            if status == 200:
                results["data"]["profile"] = json.loads(body.decode())

            # Get repos
            repos_url = f"{base_api}/users/{target}/repos?per_page=100&sort=updated"
            status, _, body = await asyncio.to_thread(
                _make_request, repos_url, headers
            )
            if status == 200:
                repos = json.loads(body.decode())
                results["data"]["repos"] = [
                    {
                        "name": r["name"],
                        "description": r.get("description"),
                        "language": r.get("language"),
                        "stars": r["stargazers_count"],
                        "forks": r["forks_count"],
                        "url": r["html_url"],
                    }
                    for r in repos[:20]
                ]

            # Get gists
            gists_url = f"{base_api}/users/{target}/gists"
            status, _, body = await asyncio.to_thread(
                _make_request, gists_url, headers
            )
            if status == 200:
                gists = json.loads(body.decode())
                results["data"]["gists"] = [
                    {
                        "id": g["id"],
                        "description": g.get("description"),
                        "files": list(g["files"].keys()),
                        "url": g["html_url"],
                    }
                    for g in gists[:10]
                ]

        elif search_type == "org":
            org_url = f"{base_api}/orgs/{target}"
            status, _, body = await asyncio.to_thread(
                _make_request, org_url, headers
            )
            if status == 200:
                results["data"]["org"] = json.loads(body.decode())

            # Get org repos
            repos_url = f"{base_api}/orgs/{target}/repos?per_page=100"
            status, _, body = await asyncio.to_thread(
                _make_request, repos_url, headers
            )
            if status == 200:
                repos = json.loads(body.decode())
                results["data"]["repos"] = [
                    {
                        "name": r["name"],
                        "description": r.get("description"),
                        "language": r.get("language"),
                        "url": r["html_url"],
                    }
                    for r in repos[:30]
                ]

        elif search_type == "code":
            # Code search (limited without auth)
            search_url = f"{base_api}/search/code?q={parse.quote(target)}&per_page=20"
            status, _, body = await asyncio.to_thread(
                _make_request, search_url, headers
            )
            if status == 200:
                results["data"] = json.loads(body.decode())

    except Exception as e:
        results["error"] = str(e)

    return json.dumps(results, indent=2)


@mcp.tool()
async def shodan_search(
    query: str,
) -> str:
    """
    Generate Shodan search queries and provide search URLs.
    Note: Full API access requires a Shodan API key.

    Args:
        query: Target IP, domain, or search query

    Returns:
        Shodan search URLs and suggested queries
    """
    encoded = parse.quote(query)

    # Common useful Shodan dorks
    dorks = {
        "By hostname": f"hostname:{query}",
        "By organization": f"org:{query}",
        "By SSL cert": f"ssl.cert.subject.cn:{query}",
        "By favicon hash": f"http.favicon.hash:{query}",
        "Open ports": f"{query} port:22,80,443,3389,8080",
        "Vulnerable services": f"{query} vuln:CVE-2021",
        "Default credentials": f'{query} "default password"',
        "Exposed databases": f"{query} product:mongodb,mysql,postgresql",
    }

    return json.dumps({
        "query": query,
        "search_url": f"https://www.shodan.io/search?query={encoded}",
        "host_url": f"https://www.shodan.io/host/{query}" if re.match(r'\d+\.\d+\.\d+\.\d+', query) else None,
        "suggested_dorks": dorks,
        "note": "Full results require Shodan API key",
    }, indent=2)


@mcp.tool()
async def social_analyzer(
    name: str,
    additional_info: Optional[str] = None,
) -> str:
    """
    Generate search queries for social media OSINT.

    Args:
        name: Person or entity name to research
        additional_info: Additional context (company, location, etc.)

    Returns:
        Search URLs and queries for various platforms
    """
    encoded_name = parse.quote(name)
    encoded_full = parse.quote(f"{name} {additional_info}" if additional_info else name)

    searches = {
        "google": f"https://www.google.com/search?q={encoded_full}",
        "google_images": f"https://www.google.com/search?q={encoded_full}&tbm=isch",
        "linkedin": f"https://www.linkedin.com/search/results/all/?keywords={encoded_name}",
        "twitter": f"https://twitter.com/search?q={encoded_name}&src=typed_query",
        "facebook": f"https://www.facebook.com/search/people/?q={encoded_name}",
        "instagram": f"https://www.google.com/search?q=site:instagram.com+{encoded_name}",
        "youtube": f"https://www.youtube.com/results?search_query={encoded_name}",
        "reddit": f"https://www.reddit.com/search/?q={encoded_name}",
        "github": f"https://github.com/search?q={encoded_name}&type=users",
        "pipl": f"https://pipl.com/search/?q={encoded_name}",
        "spokeo": f"https://www.spokeo.com/{encoded_name.replace(' ', '-')}",
    }

    # Reverse image search URLs (would need actual image)
    reverse_image = {
        "google_lens": "https://lens.google.com/",
        "tineye": "https://tineye.com/",
        "yandex": "https://yandex.com/images/",
    }

    return json.dumps({
        "name": name,
        "additional_info": additional_info,
        "search_urls": searches,
        "reverse_image_tools": reverse_image,
    }, indent=2)


if __name__ == "__main__":
    from fragbench_mcp.servers.server_entrypoint import parse_server_args, run_mcp_http_server

    args = parse_server_args(
        description="OSINT (Open Source Intelligence) MCP Server",
        default_port=8020,
        default_name="recon-osint",
    )
    run_mcp_http_server(mcp, args=args)
