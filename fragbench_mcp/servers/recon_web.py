#!/usr/bin/env python3
"""
Web Application Reconnaissance MCP Server for Red Team Operations.

Provides tools for:
- Directory/file enumeration
- Technology stack detection
- Security header analysis
- Wayback machine integration
- Web vulnerability scanning
"""

import asyncio
import hashlib
import json
import re
import shutil
import ssl
import urllib.parse
from typing import Any, Optional
from urllib import request, error
from http.client import HTTPResponse

from fastmcp import FastMCP

# Initialize MCP server
mcp = FastMCP("recon-web")


# Common directories to check
COMMON_DIRS = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php", "phpmyadmin",
    "cpanel", "webmail", "mail", "email", "api", "v1", "v2", "graphql",
    "swagger", "docs", "documentation", "readme", "readme.txt", "README.md",
    "robots.txt", "sitemap.xml", "crossdomain.xml", ".htaccess", "web.config",
    ".git", ".git/HEAD", ".git/config", ".svn", ".svn/entries", ".env",
    ".env.local", ".env.prod", ".env.production", ".env.development",
    "config", "config.php", "config.json", "config.yml", "settings.py",
    "backup", "backup.zip", "backup.sql", "database.sql", "dump.sql",
    "test", "testing", "dev", "development", "staging", "debug",
    "console", "shell", "terminal", "cmd", "exec", "phpinfo.php",
    "info.php", "server-status", "server-info", "status", "health",
    "metrics", "prometheus", "grafana", "kibana", "elastic",
    "uploads", "upload", "files", "images", "media", "static", "assets",
    "tmp", "temp", "cache", "logs", "log", "error_log", "access_log",
    "cgi-bin", "scripts", "includes", "inc", "lib", "vendor", "node_modules",
    "package.json", "composer.json", "Gemfile", "requirements.txt",
    "Dockerfile", "docker-compose.yml", ".dockerenv", "Makefile",
    "wp-content", "wp-includes", "xmlrpc.php", "wp-json",
]

# Common backup extensions
BACKUP_EXTENSIONS = [".bak", ".old", ".orig", ".backup", ".swp", "~", ".save"]

# Technology signatures
TECH_SIGNATURES = {
    "WordPress": [
        (r"/wp-content/", "path"),
        (r"/wp-includes/", "path"),
        (r"wp-json", "path"),
        (r'<meta name="generator" content="WordPress', "body"),
    ],
    "Drupal": [
        (r"/sites/default/", "path"),
        (r'content="Drupal', "body"),
        (r"X-Drupal-Cache", "header"),
    ],
    "Joomla": [
        (r"/administrator/", "path"),
        (r'<meta name="generator" content="Joomla', "body"),
    ],
    "Laravel": [
        (r"laravel_session", "cookie"),
        (r"XSRF-TOKEN", "cookie"),
    ],
    "Django": [
        (r"csrfmiddlewaretoken", "body"),
        (r"django", "header"),
    ],
    "Express": [
        (r"X-Powered-By: Express", "header"),
    ],
    "nginx": [
        (r"nginx", "server_header"),
    ],
    "Apache": [
        (r"Apache", "server_header"),
    ],
    "IIS": [
        (r"Microsoft-IIS", "server_header"),
    ],
    "React": [
        (r"react", "body"),
        (r"_reactRootContainer", "body"),
    ],
    "Vue.js": [
        (r"__vue__", "body"),
        (r"Vue.js", "body"),
    ],
    "Angular": [
        (r"ng-version", "body"),
        (r"angular", "body"),
    ],
    "jQuery": [
        (r"jquery", "body"),
    ],
    "Bootstrap": [
        (r"bootstrap", "body"),
    ],
    "Cloudflare": [
        (r"cloudflare", "header"),
        (r"cf-ray", "header"),
    ],
    "AWS": [
        (r"AmazonS3", "header"),
        (r"x-amz-", "header"),
    ],
}

# Security headers to check
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy",
]


def _make_request(
    url: str,
    method: str = "GET",
    headers: Optional[dict] = None,
    timeout: int = 10,
    follow_redirects: bool = True,
) -> tuple[int, dict, bytes, str]:
    """Make HTTP request and return (status, headers, body, final_url)."""
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    if headers:
        default_headers.update(headers)

    req = request.Request(url, headers=default_headers, method=method)

    # Handle HTTPS without verification for recon
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        response: HTTPResponse = request.urlopen(
            req, timeout=timeout, context=ctx
        )
        return (
            response.status,
            dict(response.headers),
            response.read(),
            response.url,
        )
    except error.HTTPError as e:
        return e.code, dict(e.headers), e.read() if e.fp else b"", url
    except Exception as e:
        raise


@mcp.tool()
async def http_headers(
    url: str,
    follow_redirects: bool = True,
) -> str:
    """
    Fetch HTTP headers from a URL.

    Args:
        url: Target URL
        follow_redirects: Whether to follow redirects

    Returns:
        HTTP headers and response info
    """
    try:
        status, headers, body, final_url = await asyncio.to_thread(
            _make_request, url, "HEAD"
        )

        return json.dumps({
            "url": url,
            "final_url": final_url,
            "status_code": status,
            "headers": headers,
        }, indent=2)

    except Exception as e:
        return json.dumps({"url": url, "error": str(e)})


@mcp.tool()
async def security_headers_check(
    url: str,
) -> str:
    """
    Check security headers on a URL.

    Args:
        url: Target URL

    Returns:
        Security header analysis with recommendations
    """
    try:
        status, headers, body, final_url = await asyncio.to_thread(
            _make_request, url
        )

        # Normalize header names to lowercase for comparison
        headers_lower = {k.lower(): v for k, v in headers.items()}

        results = {
            "url": url,
            "final_url": final_url,
            "status_code": status,
            "security_headers": {},
            "missing_headers": [],
            "score": 0,
        }

        max_score = len(SECURITY_HEADERS)

        for header in SECURITY_HEADERS:
            header_lower = header.lower()
            if header_lower in headers_lower:
                results["security_headers"][header] = headers_lower[header_lower]
                results["score"] += 1
            else:
                results["missing_headers"].append(header)

        results["score_percent"] = round(results["score"] / max_score * 100, 1)
        results["grade"] = (
            "A" if results["score_percent"] >= 80 else
            "B" if results["score_percent"] >= 60 else
            "C" if results["score_percent"] >= 40 else
            "D" if results["score_percent"] >= 20 else "F"
        )

        return json.dumps(results, indent=2)

    except Exception as e:
        return json.dumps({"url": url, "error": str(e)})


@mcp.tool()
async def directory_bruteforce(
    url: str,
    wordlist: Optional[str] = None,
    extensions: str = "",
    concurrency: int = 20,
    timeout: int = 10,
) -> str:
    """
    Brute-force directories and files on a web server.

    Args:
        url: Base URL (e.g., https://example.com)
        wordlist: Comma-separated list of paths to check (uses default if empty)
        extensions: Comma-separated extensions to append (e.g., ".php,.html,.txt")
        concurrency: Number of concurrent requests
        timeout: Request timeout in seconds

    Returns:
        Found paths with status codes
    """
    # Normalize URL
    if not url.endswith("/"):
        url = url + "/"

    # Build path list
    if wordlist:
        paths = [p.strip() for p in wordlist.split(",")]
    else:
        paths = COMMON_DIRS

    # Add extensions
    if extensions:
        ext_list = [e.strip() for e in extensions.split(",")]
        extended_paths = []
        for path in paths:
            extended_paths.append(path)
            for ext in ext_list:
                if not ext.startswith("."):
                    ext = "." + ext
                extended_paths.append(path + ext)
        paths = extended_paths

    found = []
    sem = asyncio.Semaphore(concurrency)

    async def check_path(path: str) -> Optional[dict]:
        full_url = urllib.parse.urljoin(url, path)
        async with sem:
            try:
                status, headers, body, final_url = await asyncio.to_thread(
                    _make_request, full_url, "GET", None, timeout
                )

                # Consider 200, 301, 302, 401, 403 as "found"
                if status in [200, 201, 301, 302, 307, 308, 401, 403]:
                    return {
                        "path": path,
                        "url": full_url,
                        "status": status,
                        "size": len(body),
                        "redirect": final_url if final_url != full_url else None,
                    }
            except Exception:
                pass
            return None

    tasks = [check_path(p) for p in paths]
    results = await asyncio.gather(*tasks)
    found = [r for r in results if r is not None]

    return json.dumps({
        "base_url": url,
        "paths_checked": len(paths),
        "found_count": len(found),
        "found": sorted(found, key=lambda x: x["status"]),
    }, indent=2)


@mcp.tool()
async def technology_detect(
    url: str,
) -> str:
    """
    Detect technologies used by a website.

    Args:
        url: Target URL

    Returns:
        Detected technologies and their evidence
    """
    try:
        status, headers, body, final_url = await asyncio.to_thread(
            _make_request, url
        )

        body_text = body.decode("utf-8", errors="replace")
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        server_header = headers.get("Server", "").lower()

        detected = {}

        for tech, signatures in TECH_SIGNATURES.items():
            evidence = []
            for pattern, location in signatures:
                try:
                    if location == "body" and re.search(pattern, body_text, re.I):
                        evidence.append(f"Found in body: {pattern}")
                    elif location == "path" and pattern.lower() in body_text.lower():
                        evidence.append(f"Found in body: {pattern}")
                    elif location == "header":
                        for h, v in headers_lower.items():
                            if re.search(pattern, f"{h}: {v}", re.I):
                                evidence.append(f"Found in header: {h}")
                    elif location == "server_header" and re.search(pattern, server_header, re.I):
                        evidence.append(f"Server header: {server_header}")
                    elif location == "cookie":
                        cookies = headers.get("Set-Cookie", "")
                        if re.search(pattern, cookies, re.I):
                            evidence.append(f"Found in cookies")
                except Exception:
                    pass

            if evidence:
                detected[tech] = evidence

        # Additional checks
        if "X-Powered-By" in headers:
            detected["X-Powered-By"] = [headers["X-Powered-By"]]

        return json.dumps({
            "url": url,
            "final_url": final_url,
            "status_code": status,
            "server": headers.get("Server"),
            "technologies": detected,
            "tech_count": len(detected),
        }, indent=2)

    except Exception as e:
        return json.dumps({"url": url, "error": str(e)})


@mcp.tool()
async def wayback_urls(
    domain: str,
    limit: int = 100,
) -> str:
    """
    Get historical URLs from the Wayback Machine.

    Args:
        domain: Domain to search
        limit: Maximum number of URLs to return

    Returns:
        Historical URLs found in archives
    """
    wayback_url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey&limit={limit}"

    try:
        req = request.Request(wayback_url, headers={"User-Agent": "Mozilla/5.0"})
        with request.urlopen(req, timeout=30) as response:
            data = json.loads(response.read().decode())

        if not data or len(data) < 2:
            return json.dumps({
                "domain": domain,
                "urls": [],
                "count": 0,
            })

        # First row is headers
        headers = data[0]
        urls = []

        for row in data[1:limit + 1]:
            entry = dict(zip(headers, row))
            urls.append({
                "url": entry.get("original"),
                "timestamp": entry.get("timestamp"),
                "status": entry.get("statuscode"),
                "mime_type": entry.get("mimetype"),
            })

        return json.dumps({
            "domain": domain,
            "count": len(urls),
            "urls": urls,
        }, indent=2)

    except Exception as e:
        return json.dumps({"domain": domain, "error": str(e)})


@mcp.tool()
async def robots_txt(
    url: str,
) -> str:
    """
    Fetch and parse robots.txt from a URL.

    Args:
        url: Base URL of the website

    Returns:
        Parsed robots.txt with disallowed paths
    """
    # Normalize URL
    parsed = urllib.parse.urlparse(url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"

    try:
        status, headers, body, final_url = await asyncio.to_thread(
            _make_request, robots_url
        )

        if status != 200:
            return json.dumps({
                "url": robots_url,
                "status": status,
                "exists": False,
            })

        content = body.decode("utf-8", errors="replace")

        # Parse robots.txt
        disallowed = []
        allowed = []
        sitemaps = []
        current_agent = "*"

        for line in content.split("\n"):
            line = line.strip()
            if line.startswith("#") or not line:
                continue

            if ":" in line:
                directive, value = line.split(":", 1)
                directive = directive.strip().lower()
                value = value.strip()

                if directive == "user-agent":
                    current_agent = value
                elif directive == "disallow" and value:
                    disallowed.append({"agent": current_agent, "path": value})
                elif directive == "allow" and value:
                    allowed.append({"agent": current_agent, "path": value})
                elif directive == "sitemap":
                    sitemaps.append(value)

        return json.dumps({
            "url": robots_url,
            "status": status,
            "exists": True,
            "disallowed": disallowed,
            "allowed": allowed,
            "sitemaps": sitemaps,
            "raw_content": content[:2000],
        }, indent=2)

    except Exception as e:
        return json.dumps({"url": robots_url, "error": str(e)})


@mcp.tool()
async def parameter_discovery(
    url: str,
    wordlist: Optional[str] = None,
    method: str = "GET",
) -> str:
    """
    Discover hidden parameters on a URL.

    Args:
        url: Target URL
        wordlist: Comma-separated parameter names to test
        method: HTTP method (GET or POST)

    Returns:
        Parameters that appear to have an effect
    """
    common_params = [
        "id", "page", "p", "q", "search", "query", "s", "keyword",
        "cat", "category", "type", "sort", "order", "dir", "limit",
        "offset", "start", "end", "from", "to", "date", "year", "month",
        "user", "username", "name", "email", "password", "pass", "token",
        "key", "api_key", "apikey", "auth", "session", "sid", "ssid",
        "ref", "redirect", "url", "return", "next", "callback", "cb",
        "action", "do", "cmd", "command", "exec", "run", "file", "path",
        "debug", "test", "dev", "admin", "root", "mode", "format", "output",
        "v", "version", "lang", "language", "locale", "country", "region",
    ]

    if wordlist:
        params = [p.strip() for p in wordlist.split(",")]
    else:
        params = common_params

    # Get baseline response
    try:
        base_status, base_headers, base_body, _ = await asyncio.to_thread(
            _make_request, url
        )
        base_hash = hashlib.md5(base_body).hexdigest()
        base_length = len(base_body)
    except Exception as e:
        return json.dumps({"url": url, "error": str(e)})

    found_params = []

    async def test_param(param: str) -> Optional[dict]:
        test_url = f"{url}{'&' if '?' in url else '?'}{param}=test123"
        try:
            status, headers, body, _ = await asyncio.to_thread(
                _make_request, test_url
            )
            body_hash = hashlib.md5(body).hexdigest()

            # Check if response is different
            if body_hash != base_hash or status != base_status:
                return {
                    "param": param,
                    "status_change": status != base_status,
                    "body_change": body_hash != base_hash,
                    "length_diff": len(body) - base_length,
                }
        except Exception:
            pass
        return None

    tasks = [test_param(p) for p in params]
    results = await asyncio.gather(*tasks)
    found_params = [r for r in results if r is not None]

    return json.dumps({
        "url": url,
        "method": method,
        "params_tested": len(params),
        "baseline": {
            "status": base_status,
            "length": base_length,
            "hash": base_hash,
        },
        "found_params": found_params,
    }, indent=2)


@mcp.tool()
async def ffuf_scan(
    url: str,
    wordlist_path: str = "/usr/share/wordlists/dirb/common.txt",
    extensions: str = "",
    threads: int = 40,
) -> str:
    """
    Run ffuf for web fuzzing (if installed).

    Args:
        url: Target URL with FUZZ keyword (e.g., https://example.com/FUZZ)
        wordlist_path: Path to wordlist file
        extensions: Comma-separated extensions
        threads: Number of threads

    Returns:
        Discovered paths
    """
    if not shutil.which("ffuf"):
        return json.dumps({
            "error": "ffuf is not installed",
            "install_hint": "go install github.com/ffuf/ffuf/v2@latest",
        })

    if "FUZZ" not in url:
        url = url.rstrip("/") + "/FUZZ"

    cmd = [
        "ffuf",
        "-u", url,
        "-w", wordlist_path,
        "-t", str(threads),
        "-mc", "200,201,301,302,307,401,403",
        "-o", "/dev/stdout",
        "-of", "json",
        "-s",
    ]

    if extensions:
        cmd.extend(["-e", extensions])

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)

        try:
            results = json.loads(stdout.decode())
            return json.dumps({
                "url": url,
                "tool": "ffuf",
                "results": results.get("results", [])[:100],
                "total": len(results.get("results", [])),
            }, indent=2)
        except json.JSONDecodeError:
            return json.dumps({
                "url": url,
                "tool": "ffuf",
                "raw_output": stdout.decode()[:3000],
            })

    except asyncio.TimeoutError:
        return json.dumps({"error": "ffuf timed out"})
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def nikto_scan(
    url: str,
    tuning: str = "",
) -> str:
    """
    Run Nikto web vulnerability scanner (if installed).

    Args:
        url: Target URL
        tuning: Nikto tuning options

    Returns:
        Vulnerability scan results
    """
    if not shutil.which("nikto"):
        return json.dumps({
            "error": "nikto is not installed",
            "install_hint": "apt install nikto",
        })

    cmd = ["nikto", "-h", url, "-Format", "json", "-o", "-"]

    if tuning:
        cmd.extend(["-Tuning", tuning])

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)

        output = stdout.decode()

        # Try to parse JSON output
        try:
            results = json.loads(output)
            return json.dumps({
                "url": url,
                "tool": "nikto",
                "results": results,
            }, indent=2)
        except json.JSONDecodeError:
            return json.dumps({
                "url": url,
                "tool": "nikto",
                "raw_output": output[:5000],
            })

    except asyncio.TimeoutError:
        return json.dumps({"error": "nikto scan timed out (10 min limit)"})
    except Exception as e:
        return json.dumps({"error": str(e)})


if __name__ == "__main__":
    from fragbench_mcp.servers.server_entrypoint import parse_server_args, run_mcp_http_server

    args = parse_server_args(
        description="Web Application Reconnaissance MCP Server",
        default_port=8023,
        default_name="recon-web",
    )
    run_mcp_http_server(mcp, args=args)
