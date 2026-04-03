#!/usr/bin/env python3
"""
Cloud Reconnaissance MCP Server

Provides cloud infrastructure reconnaissance capabilities:
- AWS S3 bucket enumeration
- Azure blob storage discovery
- GCP storage bucket scanning
- Cloud metadata service detection
- Cloud provider identification
- Subdomain-to-cloud correlation
"""

import asyncio
import json
import re
import socket
from typing import Optional, List
from urllib.parse import urlparse
import urllib.request
import urllib.error

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "_shared"))

from fastmcp import FastMCP

mcp = FastMCP("cloud_recon")

# Cloud provider patterns
CLOUD_PATTERNS = {
    "aws": {
        "s3_patterns": [
            r"s3\.amazonaws\.com",
            r"s3-[\w-]+\.amazonaws\.com",
            r"[\w.-]+\.s3\.amazonaws\.com",
            r"[\w.-]+\.s3-[\w-]+\.amazonaws\.com",
        ],
        "cloudfront": r"[\w]+\.cloudfront\.net",
        "ec2": r"ec2-[\d-]+\.[\w-]+\.compute\.amazonaws\.com",
        "elb": r"[\w-]+\.[\w-]+\.elb\.amazonaws\.com",
        "api_gateway": r"[\w]+\.execute-api\.[\w-]+\.amazonaws\.com",
        "lambda": r"[\w]+\.lambda-url\.[\w-]+\.on\.aws",
    },
    "azure": {
        "blob": r"[\w-]+\.blob\.core\.windows\.net",
        "websites": r"[\w-]+\.azurewebsites\.net",
        "cdn": r"[\w-]+\.azureedge\.net",
        "cloudapp": r"[\w-]+\.cloudapp\.azure\.com",
        "database": r"[\w-]+\.database\.windows\.net",
    },
    "gcp": {
        "storage": r"storage\.googleapis\.com/[\w.-]+",
        "storage_bucket": r"[\w.-]+\.storage\.googleapis\.com",
        "appspot": r"[\w-]+\.appspot\.com",
        "cloudfunctions": r"[\w-]+\.cloudfunctions\.net",
        "run": r"[\w-]+\.run\.app",
    },
    "digitalocean": {
        "spaces": r"[\w-]+\.[\w-]+\.digitaloceanspaces\.com",
        "app": r"[\w-]+\.ondigitalocean\.app",
    },
}

# Common S3 bucket names to test
COMMON_BUCKET_PREFIXES = [
    "", "dev", "development", "staging", "stage", "prod", "production",
    "test", "testing", "backup", "backups", "data", "files", "assets",
    "media", "images", "static", "logs", "archive", "temp", "tmp",
    "private", "public", "internal", "external", "web", "app", "api",
    "cdn", "content", "uploads", "downloads", "docs", "documents",
]

COMMON_BUCKET_SUFFIXES = [
    "", "-dev", "-development", "-staging", "-stage", "-prod", "-production",
    "-test", "-backup", "-data", "-files", "-assets", "-media", "-static",
    "-logs", "-archive", "-private", "-public", "-web", "-app", "-api",
    "-bucket", "-storage", "-s3", "-aws",
]


@mcp.tool()
async def enumerate_s3_buckets(
    target: str,
    wordlist: str = "common",
    concurrency: int = 20,
    timeout: int = 5,
) -> str:
    """
    Enumerate S3 buckets for a target organization.

    Args:
        target: Organization name or domain to derive bucket names from
        wordlist: Wordlist type (common, extended, or comma-separated custom words)
        concurrency: Number of concurrent checks
        timeout: Request timeout per bucket in seconds

    Returns:
        JSON with discovered S3 buckets and their status
    """
    # Clean target name
    base_name = target.lower().replace(" ", "-").replace(".", "-")
    base_name = re.sub(r"[^a-z0-9-]", "", base_name)

    # Generate bucket names
    bucket_names = set()

    if wordlist == "common":
        prefixes = COMMON_BUCKET_PREFIXES[:15]
        suffixes = COMMON_BUCKET_SUFFIXES[:15]
    elif wordlist == "extended":
        prefixes = COMMON_BUCKET_PREFIXES
        suffixes = COMMON_BUCKET_SUFFIXES
    else:
        # Custom wordlist
        custom_words = [w.strip() for w in wordlist.split(",")]
        prefixes = custom_words
        suffixes = [""]

    for prefix in prefixes:
        for suffix in suffixes:
            if prefix:
                bucket_names.add(f"{prefix}-{base_name}{suffix}")
                bucket_names.add(f"{base_name}-{prefix}{suffix}")
            else:
                bucket_names.add(f"{base_name}{suffix}")

    # Also try with domain parts
    domain_parts = base_name.split("-")
    if len(domain_parts) > 1:
        bucket_names.add(domain_parts[0])
        bucket_names.add("-".join(domain_parts[:2]))

    results = {
        "target": target,
        "buckets_checked": len(bucket_names),
        "found": [],
        "accessible": [],
        "denied": [],
    }

    sem = asyncio.Semaphore(concurrency)

    async def check_bucket(bucket_name: str):
        async with sem:
            status = await _check_s3_bucket(bucket_name, timeout)
            return bucket_name, status

    tasks = [check_bucket(name) for name in bucket_names]
    check_results = await asyncio.gather(*tasks)

    for bucket_name, status in check_results:
        if status["exists"]:
            bucket_info = {
                "name": bucket_name,
                "url": f"https://{bucket_name}.s3.amazonaws.com",
                "status": status["status"],
                "public": status.get("public", False),
            }
            results["found"].append(bucket_info)

            if status.get("public"):
                results["accessible"].append(bucket_info)
            elif status["status"] == "access_denied":
                results["denied"].append(bucket_info)

    return json.dumps(results, indent=2)


async def _check_s3_bucket(bucket_name: str, timeout: int) -> dict:
    """Check if an S3 bucket exists and its access status."""
    url = f"https://{bucket_name}.s3.amazonaws.com"

    try:
        req = urllib.request.Request(url, method="HEAD")
        req.add_header("User-Agent", "Mozilla/5.0 (compatible; Red-APT/1.0)")

        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: urllib.request.urlopen(req, timeout=timeout)
        )

        return {
            "exists": True,
            "status": "public",
            "public": True,
            "code": response.getcode(),
        }

    except urllib.error.HTTPError as e:
        if e.code == 403:
            return {"exists": True, "status": "access_denied", "public": False}
        elif e.code == 404:
            return {"exists": False, "status": "not_found"}
        else:
            return {"exists": True, "status": f"http_{e.code}", "public": False}

    except Exception:
        return {"exists": False, "status": "error"}


@mcp.tool()
async def check_s3_bucket(
    bucket_name: str,
    check_acl: bool = True,
    list_objects: bool = True,
) -> str:
    """
    Check a specific S3 bucket for access and list contents if accessible.

    Args:
        bucket_name: S3 bucket name to check
        check_acl: Attempt to retrieve bucket ACL
        list_objects: Attempt to list bucket objects

    Returns:
        JSON with bucket status, ACL, and object listing
    """
    results = {
        "bucket": bucket_name,
        "url": f"https://{bucket_name}.s3.amazonaws.com",
        "exists": False,
        "public_access": False,
        "acl": None,
        "objects": [],
    }

    # Check bucket existence
    try:
        req = urllib.request.Request(
            f"https://{bucket_name}.s3.amazonaws.com",
            method="HEAD"
        )
        req.add_header("User-Agent", "Mozilla/5.0")

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            lambda: urllib.request.urlopen(req, timeout=10)
        )
        results["exists"] = True
        results["public_access"] = True

    except urllib.error.HTTPError as e:
        if e.code == 403:
            results["exists"] = True
            results["public_access"] = False
            results["status"] = "Access Denied - bucket exists but is not public"
        elif e.code == 404:
            results["status"] = "Bucket does not exist"
            return json.dumps(results, indent=2)
        else:
            results["exists"] = True
            results["status"] = f"HTTP {e.code}"

    except Exception as e:
        results["status"] = f"Error: {str(e)}"
        return json.dumps(results, indent=2)

    # Try to list objects if accessible
    if results["public_access"] and list_objects:
        try:
            req = urllib.request.Request(f"https://{bucket_name}.s3.amazonaws.com")
            req.add_header("User-Agent", "Mozilla/5.0")

            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: urllib.request.urlopen(req, timeout=15)
            )

            content = response.read().decode()

            # Parse XML listing
            import xml.etree.ElementTree as ET
            root = ET.fromstring(content)

            # Handle namespace
            ns = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}

            for contents in root.findall(".//s3:Contents", ns):
                key = contents.find("s3:Key", ns)
                size = contents.find("s3:Size", ns)
                modified = contents.find("s3:LastModified", ns)

                if key is not None:
                    results["objects"].append({
                        "key": key.text,
                        "size": int(size.text) if size is not None else 0,
                        "last_modified": modified.text if modified is not None else None,
                    })

            results["object_count"] = len(results["objects"])

            # Check for sensitive files
            sensitive_patterns = [
                r"\.env", r"\.git", r"\.aws", r"credentials",
                r"password", r"secret", r"key", r"\.pem", r"\.pfx",
                r"backup", r"dump", r"\.sql", r"\.db",
            ]

            results["potentially_sensitive"] = [
                obj for obj in results["objects"]
                if any(re.search(pattern, obj["key"], re.I) for pattern in sensitive_patterns)
            ]

        except Exception as e:
            results["list_error"] = str(e)

    # Try to check ACL
    if results["exists"] and check_acl:
        try:
            req = urllib.request.Request(f"https://{bucket_name}.s3.amazonaws.com/?acl")
            req.add_header("User-Agent", "Mozilla/5.0")

            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: urllib.request.urlopen(req, timeout=10)
            )

            results["acl"] = "ACL accessible - review for overly permissive grants"
            results["acl_content"] = response.read().decode()[:1000]

        except urllib.error.HTTPError:
            results["acl"] = "ACL not accessible"
        except Exception:
            pass

    return json.dumps(results, indent=2)


@mcp.tool()
async def enumerate_azure_blobs(
    target: str,
    concurrency: int = 20,
) -> str:
    """
    Enumerate Azure Blob Storage containers for a target.

    Args:
        target: Organization name or storage account name
        concurrency: Number of concurrent checks

    Returns:
        JSON with discovered Azure storage accounts and containers
    """
    base_name = target.lower().replace(" ", "").replace("-", "").replace(".", "")
    base_name = re.sub(r"[^a-z0-9]", "", base_name)[:24]  # Azure limit

    # Generate storage account names
    storage_accounts = set()
    suffixes = ["", "storage", "store", "data", "blob", "files", "backup", "dev", "prod"]

    for suffix in suffixes:
        name = f"{base_name}{suffix}"[:24]
        if len(name) >= 3:
            storage_accounts.add(name)

    results = {
        "target": target,
        "accounts_checked": len(storage_accounts),
        "found": [],
    }

    sem = asyncio.Semaphore(concurrency)

    async def check_account(account_name: str):
        async with sem:
            url = f"https://{account_name}.blob.core.windows.net"
            try:
                req = urllib.request.Request(url, method="HEAD")
                req.add_header("User-Agent", "Mozilla/5.0")

                loop = asyncio.get_event_loop()
                await loop.run_in_executor(
                    None,
                    lambda: urllib.request.urlopen(req, timeout=5)
                )
                return {"name": account_name, "url": url, "status": "exists"}

            except urllib.error.HTTPError as e:
                if e.code in [400, 403, 404]:
                    if e.code == 400:
                        return {"name": account_name, "url": url, "status": "exists"}
                return None
            except Exception:
                return None

    tasks = [check_account(name) for name in storage_accounts]
    check_results = await asyncio.gather(*tasks)

    for result in check_results:
        if result:
            results["found"].append(result)

    # Try common container names for found accounts
    common_containers = ["$root", "$web", "files", "data", "backup", "public", "private"]

    for account in results["found"]:
        account["containers"] = []
        for container in common_containers:
            try:
                url = f"{account['url']}/{container}?restype=container&comp=list"
                req = urllib.request.Request(url)
                req.add_header("User-Agent", "Mozilla/5.0")

                loop = asyncio.get_event_loop()
                await loop.run_in_executor(
                    None,
                    lambda: urllib.request.urlopen(req, timeout=5)
                )
                account["containers"].append({
                    "name": container,
                    "status": "public_list",
                })
            except urllib.error.HTTPError as e:
                if e.code == 403:
                    account["containers"].append({
                        "name": container,
                        "status": "exists_private",
                    })
            except Exception:
                pass

    return json.dumps(results, indent=2)


@mcp.tool()
async def enumerate_gcp_buckets(
    target: str,
    concurrency: int = 20,
) -> str:
    """
    Enumerate GCP Storage buckets for a target.

    Args:
        target: Organization name or project name
        concurrency: Number of concurrent checks

    Returns:
        JSON with discovered GCP storage buckets
    """
    base_name = target.lower().replace(" ", "-").replace(".", "-")
    base_name = re.sub(r"[^a-z0-9-]", "", base_name)

    # Generate bucket names
    bucket_names = set()
    for prefix in COMMON_BUCKET_PREFIXES[:15]:
        for suffix in ["-gcp", "-gcs", "-bucket", ""]:
            if prefix:
                bucket_names.add(f"{prefix}-{base_name}{suffix}")
            bucket_names.add(f"{base_name}{suffix}")

    results = {
        "target": target,
        "buckets_checked": len(bucket_names),
        "found": [],
    }

    sem = asyncio.Semaphore(concurrency)

    async def check_bucket(bucket_name: str):
        async with sem:
            url = f"https://storage.googleapis.com/{bucket_name}"
            try:
                req = urllib.request.Request(url, method="HEAD")
                req.add_header("User-Agent", "Mozilla/5.0")

                loop = asyncio.get_event_loop()
                response = await loop.run_in_executor(
                    None,
                    lambda: urllib.request.urlopen(req, timeout=5)
                )
                return {
                    "name": bucket_name,
                    "url": url,
                    "status": "public",
                    "public": True,
                }

            except urllib.error.HTTPError as e:
                if e.code == 403:
                    return {
                        "name": bucket_name,
                        "url": url,
                        "status": "access_denied",
                        "public": False,
                    }
                return None
            except Exception:
                return None

    tasks = [check_bucket(name) for name in bucket_names]
    check_results = await asyncio.gather(*tasks)

    for result in check_results:
        if result:
            results["found"].append(result)

    return json.dumps(results, indent=2)


@mcp.tool()
async def detect_cloud_provider(
    target: str,
) -> str:
    """
    Detect which cloud provider(s) a target is using based on DNS and HTTP analysis.

    Args:
        target: Target domain to analyze

    Returns:
        JSON with detected cloud providers and evidence
    """
    results = {
        "target": target,
        "providers": [],
        "evidence": [],
    }

    # Clean target
    if target.startswith(("http://", "https://")):
        target = urlparse(target).netloc
    target = target.strip("/")

    # DNS resolution check
    try:
        loop = asyncio.get_event_loop()
        ips = await loop.run_in_executor(None, socket.gethostbyname_ex, target)

        results["dns"] = {
            "hostname": ips[0],
            "aliases": ips[1],
            "addresses": ips[2],
        }

        # Check IP ranges for cloud providers
        for ip in ips[2]:
            ip_info = await _check_ip_cloud_provider(ip)
            if ip_info:
                results["evidence"].append(ip_info)

    except socket.gaierror:
        results["dns_error"] = "Failed to resolve hostname"

    # Check CNAME records for cloud patterns
    try:
        import subprocess
        process = await asyncio.create_subprocess_exec(
            "dig", "+short", "CNAME", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await process.communicate()
        cnames = stdout.decode().strip().split("\n")

        for cname in cnames:
            if cname:
                for provider, patterns in CLOUD_PATTERNS.items():
                    for pattern_name, pattern in patterns.items():
                        if re.search(pattern, cname, re.I):
                            results["evidence"].append({
                                "type": "cname",
                                "provider": provider,
                                "service": pattern_name,
                                "value": cname,
                            })
    except Exception:
        pass

    # HTTP header analysis
    try:
        req = urllib.request.Request(f"https://{target}")
        req.add_header("User-Agent", "Mozilla/5.0")

        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: urllib.request.urlopen(req, timeout=10)
        )

        headers = dict(response.headers)
        results["headers"] = headers

        # Check headers for cloud indicators
        header_indicators = {
            "x-amz-": "aws",
            "x-amzn-": "aws",
            "x-ms-": "azure",
            "x-azure-": "azure",
            "x-goog-": "gcp",
            "x-cloud-trace-context": "gcp",
            "cf-ray": "cloudflare",
            "x-cache": "cdn",
        }

        for key, value in headers.items():
            key_lower = key.lower()
            for indicator, provider in header_indicators.items():
                if indicator in key_lower:
                    results["evidence"].append({
                        "type": "header",
                        "provider": provider,
                        "header": key,
                        "value": value[:100],
                    })

        # Check server header
        server = headers.get("Server", "")
        if "cloudflare" in server.lower():
            results["evidence"].append({"type": "server", "provider": "cloudflare", "value": server})
        elif "AmazonS3" in server:
            results["evidence"].append({"type": "server", "provider": "aws", "service": "s3", "value": server})
        elif "Microsoft" in server:
            results["evidence"].append({"type": "server", "provider": "azure", "value": server})

    except Exception as e:
        results["http_error"] = str(e)

    # Compile unique providers
    seen_providers = set()
    for evidence in results["evidence"]:
        seen_providers.add(evidence["provider"])

    results["providers"] = list(seen_providers)
    results["summary"] = {
        "primary_provider": results["providers"][0] if results["providers"] else "unknown",
        "total_evidence_points": len(results["evidence"]),
    }

    return json.dumps(results, indent=2)


async def _check_ip_cloud_provider(ip: str) -> Optional[dict]:
    """Check if an IP belongs to a known cloud provider."""
    # AWS IP ranges (simplified)
    aws_prefixes = ["3.", "13.", "15.", "18.", "34.", "35.", "44.", "50.", "52.", "54.", "99."]
    azure_prefixes = ["13.", "20.", "40.", "51.", "52.", "65.", "104.", "137.", "168."]
    gcp_prefixes = ["8.34.", "8.35.", "34.", "35.", "104."]

    for prefix in aws_prefixes:
        if ip.startswith(prefix):
            return {"type": "ip_range", "provider": "aws", "ip": ip}

    for prefix in azure_prefixes:
        if ip.startswith(prefix):
            return {"type": "ip_range", "provider": "azure", "ip": ip}

    for prefix in gcp_prefixes:
        if ip.startswith(prefix):
            return {"type": "ip_range", "provider": "gcp", "ip": ip}

    return None


@mcp.tool()
async def check_metadata_service(
    target: str,
    timeout: int = 5,
) -> str:
    """
    Check if cloud metadata service is accessible (SSRF vulnerability indicator).

    Args:
        target: Target URL to test for metadata access
        timeout: Request timeout in seconds

    Returns:
        JSON with metadata service accessibility status
    """
    metadata_endpoints = {
        "aws": {
            "url": "http://169.254.169.254/latest/meta-data/",
            "token_url": "http://169.254.169.254/latest/api/token",
        },
        "azure": {
            "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "header": {"Metadata": "true"},
        },
        "gcp": {
            "url": "http://metadata.google.internal/computeMetadata/v1/",
            "header": {"Metadata-Flavor": "Google"},
        },
        "digitalocean": {
            "url": "http://169.254.169.254/metadata/v1/",
        },
    }

    results = {
        "target": target,
        "metadata_accessible": False,
        "findings": [],
        "ssrf_risk": "unknown",
    }

    # Direct metadata check (if running on cloud instance)
    for provider, config in metadata_endpoints.items():
        try:
            req = urllib.request.Request(config["url"])
            if "header" in config:
                for key, value in config["header"].items():
                    req.add_header(key, value)

            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: urllib.request.urlopen(req, timeout=timeout)
            )

            content = response.read().decode()[:500]
            results["metadata_accessible"] = True
            results["findings"].append({
                "provider": provider,
                "endpoint": config["url"],
                "status": "accessible",
                "sample": content,
            })
            results["ssrf_risk"] = "high"

        except Exception:
            results["findings"].append({
                "provider": provider,
                "endpoint": config["url"],
                "status": "not_accessible",
            })

    # Generate SSRF test payloads
    results["ssrf_test_payloads"] = [
        "http://169.254.169.254/latest/meta-data/",
        "http://[::ffff:169.254.169.254]/latest/meta-data/",
        "http://169.254.169.254.xip.io/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/instance",
    ]

    return json.dumps(results, indent=2)


@mcp.tool()
async def subdomain_cloud_correlation(
    subdomains: str,
) -> str:
    """
    Correlate a list of subdomains with cloud services.

    Args:
        subdomains: JSON array or comma-separated list of subdomains

    Returns:
        JSON with cloud service mappings for each subdomain
    """
    # Parse input
    try:
        subdomain_list = json.loads(subdomains)
    except json.JSONDecodeError:
        subdomain_list = [s.strip() for s in subdomains.split(",")]

    results = {
        "total_subdomains": len(subdomain_list),
        "cloud_services": [],
        "by_provider": {},
    }

    for subdomain in subdomain_list:
        subdomain = subdomain.strip().lower()

        # Check against cloud patterns
        for provider, patterns in CLOUD_PATTERNS.items():
            for service, pattern in patterns.items():
                if re.search(pattern, subdomain, re.I):
                    finding = {
                        "subdomain": subdomain,
                        "provider": provider,
                        "service": service,
                    }
                    results["cloud_services"].append(finding)

                    if provider not in results["by_provider"]:
                        results["by_provider"][provider] = []
                    results["by_provider"][provider].append(finding)
                    break

    # Add summary
    results["summary"] = {
        "cloud_related": len(results["cloud_services"]),
        "providers_found": list(results["by_provider"].keys()),
    }

    return json.dumps(results, indent=2)


@mcp.tool()
async def cloud_misconfig_check(
    target: str,
    provider: str = "all",
) -> str:
    """
    Check for common cloud misconfigurations.

    Args:
        target: Target organization name or domain
        provider: Cloud provider to check (aws, azure, gcp, or all)

    Returns:
        JSON with potential misconfigurations found
    """
    results = {
        "target": target,
        "provider_filter": provider,
        "checks_performed": [],
        "findings": [],
        "recommendations": [],
    }

    base_name = target.lower().replace(" ", "-").replace(".", "-")
    base_name = re.sub(r"[^a-z0-9-]", "", base_name)

    # AWS checks
    if provider in ["all", "aws"]:
        results["checks_performed"].append("aws_s3_public")

        # Check for public S3 buckets
        test_buckets = [base_name, f"{base_name}-backup", f"{base_name}-data", f"{base_name}-public"]
        for bucket in test_buckets:
            try:
                url = f"https://{bucket}.s3.amazonaws.com"
                req = urllib.request.Request(url)
                req.add_header("User-Agent", "Mozilla/5.0")

                loop = asyncio.get_event_loop()
                await loop.run_in_executor(
                    None,
                    lambda: urllib.request.urlopen(req, timeout=5)
                )

                results["findings"].append({
                    "type": "public_s3_bucket",
                    "provider": "aws",
                    "resource": bucket,
                    "severity": "high",
                    "url": url,
                })
            except urllib.error.HTTPError as e:
                if e.code == 403:
                    # Bucket exists but private - good
                    pass
            except Exception:
                pass

    # Azure checks
    if provider in ["all", "azure"]:
        results["checks_performed"].append("azure_blob_public")

        storage_name = base_name.replace("-", "")[:24]
        test_containers = ["$web", "public", "files"]

        for container in test_containers:
            try:
                url = f"https://{storage_name}.blob.core.windows.net/{container}?restype=container&comp=list"
                req = urllib.request.Request(url)
                req.add_header("User-Agent", "Mozilla/5.0")

                loop = asyncio.get_event_loop()
                await loop.run_in_executor(
                    None,
                    lambda: urllib.request.urlopen(req, timeout=5)
                )

                results["findings"].append({
                    "type": "public_azure_container",
                    "provider": "azure",
                    "resource": f"{storage_name}/{container}",
                    "severity": "high",
                    "url": url,
                })
            except Exception:
                pass

    # GCP checks
    if provider in ["all", "gcp"]:
        results["checks_performed"].append("gcp_bucket_public")

        test_buckets = [base_name, f"{base_name}-public", f"{base_name}-data"]
        for bucket in test_buckets:
            try:
                url = f"https://storage.googleapis.com/{bucket}"
                req = urllib.request.Request(url)
                req.add_header("User-Agent", "Mozilla/5.0")

                loop = asyncio.get_event_loop()
                await loop.run_in_executor(
                    None,
                    lambda: urllib.request.urlopen(req, timeout=5)
                )

                results["findings"].append({
                    "type": "public_gcp_bucket",
                    "provider": "gcp",
                    "resource": bucket,
                    "severity": "high",
                    "url": url,
                })
            except Exception:
                pass

    # Generate recommendations
    if results["findings"]:
        results["recommendations"] = [
            "Review and restrict public access to cloud storage resources",
            "Enable access logging for all storage buckets",
            "Implement bucket policies with principle of least privilege",
            "Use private endpoints where possible",
            "Enable encryption at rest and in transit",
        ]
    else:
        results["recommendations"] = [
            "No obvious misconfigurations found in quick scan",
            "Consider deeper analysis with cloud-specific tools",
            "Review IAM policies and access controls manually",
        ]

    results["summary"] = {
        "findings_count": len(results["findings"]),
        "high_severity": sum(1 for f in results["findings"] if f.get("severity") == "high"),
    }

    return json.dumps(results, indent=2)


@mcp.tool()
async def generate_cloud_wordlist(
    target: str,
    provider: str = "all",
    format: str = "list",
) -> str:
    """
    Generate a wordlist for cloud resource enumeration.

    Args:
        target: Organization name to base wordlist on
        provider: Target provider (aws, azure, gcp, all)
        format: Output format (list, json, nuclei)

    Returns:
        Generated wordlist for cloud enumeration
    """
    base_name = target.lower().replace(" ", "-").replace(".", "-")
    base_name = re.sub(r"[^a-z0-9-]", "", base_name)

    wordlist = []

    # S3/GCS bucket names (aws, gcp)
    if provider in ["all", "aws", "gcp"]:
        for prefix in COMMON_BUCKET_PREFIXES:
            for suffix in COMMON_BUCKET_SUFFIXES:
                if prefix:
                    wordlist.append(f"{prefix}-{base_name}{suffix}")
                    wordlist.append(f"{base_name}-{prefix}{suffix}")
                else:
                    wordlist.append(f"{base_name}{suffix}")

    # Azure storage account names (no hyphens, max 24 chars)
    if provider in ["all", "azure"]:
        azure_name = base_name.replace("-", "")[:24]
        azure_suffixes = ["storage", "store", "data", "blob", "files", "backup", ""]
        for suffix in azure_suffixes:
            name = f"{azure_name}{suffix}"[:24]
            if len(name) >= 3:
                wordlist.append(name)

    wordlist = sorted(set(wordlist))

    if format == "json":
        return json.dumps({
            "target": target,
            "provider": provider,
            "wordlist": wordlist,
            "count": len(wordlist),
        }, indent=2)

    elif format == "nuclei":
        # Generate nuclei template
        template = f"""id: cloud-enum-{base_name}
info:
  name: Cloud Resource Enumeration - {target}
  severity: info

requests:
  - method: HEAD
    path:
"""
        for word in wordlist[:50]:
            template += f'      - "https://{word}.s3.amazonaws.com"\n'
            template += f'      - "https://storage.googleapis.com/{word}"\n'

        return template

    else:
        return "\n".join(wordlist)


if __name__ == "__main__":
    from server_entrypoint import parse_server_args, run_mcp_http_server

    args = parse_server_args(
        description="Cloud Reconnaissance MCP Server",
        default_port=8024,
        default_name="cloud_recon",
    )
    run_mcp_http_server(mcp, args=args)
