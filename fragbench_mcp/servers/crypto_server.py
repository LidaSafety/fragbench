#!/usr/bin/env python3
"""
Crypto & Credentials MCP Server

Provides cryptography and credential testing capabilities:
- Hash identification and analysis
- Hash cracking (hashcat wrapper)
- JWT decode/tamper/forge
- Password list generation
- Credential validation
- Encryption/decryption utilities
"""

import asyncio
import base64
import hashlib
import hmac
import json
import re
import secrets
import shutil
import string
from datetime import datetime, timedelta
from typing import Optional, List
from pathlib import Path

from fastmcp import FastMCP

mcp = FastMCP("crypto")

# Hash patterns for identification
HASH_PATTERNS = {
    "md5": {
        "regex": r"^[a-fA-F0-9]{32}$",
        "length": 32,
        "hashcat_mode": 0,
        "description": "MD5",
    },
    "sha1": {
        "regex": r"^[a-fA-F0-9]{40}$",
        "length": 40,
        "hashcat_mode": 100,
        "description": "SHA-1",
    },
    "sha256": {
        "regex": r"^[a-fA-F0-9]{64}$",
        "length": 64,
        "hashcat_mode": 1400,
        "description": "SHA-256",
    },
    "sha512": {
        "regex": r"^[a-fA-F0-9]{128}$",
        "length": 128,
        "hashcat_mode": 1700,
        "description": "SHA-512",
    },
    "ntlm": {
        "regex": r"^[a-fA-F0-9]{32}$",
        "length": 32,
        "hashcat_mode": 1000,
        "description": "NTLM",
    },
    "mysql": {
        "regex": r"^\*[A-F0-9]{40}$",
        "length": 41,
        "hashcat_mode": 300,
        "description": "MySQL 4.1+",
    },
    "bcrypt": {
        "regex": r"^\$2[ayb]\$\d{2}\$[./A-Za-z0-9]{53}$",
        "length": 60,
        "hashcat_mode": 3200,
        "description": "bcrypt",
    },
    "sha512crypt": {
        "regex": r"^\$6\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{86}$",
        "length": None,
        "hashcat_mode": 1800,
        "description": "SHA-512 Crypt (Unix)",
    },
    "sha256crypt": {
        "regex": r"^\$5\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{43}$",
        "length": None,
        "hashcat_mode": 7400,
        "description": "SHA-256 Crypt (Unix)",
    },
    "md5crypt": {
        "regex": r"^\$1\$[./A-Za-z0-9]{8}\$[./A-Za-z0-9]{22}$",
        "length": None,
        "hashcat_mode": 500,
        "description": "MD5 Crypt (Unix)",
    },
    "argon2": {
        "regex": r"^\$argon2(i|d|id)\$",
        "length": None,
        "hashcat_mode": None,
        "description": "Argon2",
    },
    "pbkdf2_sha256": {
        "regex": r"^pbkdf2_sha256\$",
        "length": None,
        "hashcat_mode": 10000,
        "description": "PBKDF2-SHA256 (Django)",
    },
    "wordpress": {
        "regex": r"^\$P\$[./A-Za-z0-9]{31}$",
        "length": 34,
        "hashcat_mode": 400,
        "description": "WordPress (phpass)",
    },
    "lm": {
        "regex": r"^[a-fA-F0-9]{32}$",
        "length": 32,
        "hashcat_mode": 3000,
        "description": "LM Hash",
    },
}

# Common passwords for quick checks
COMMON_PASSWORDS = [
    "password", "123456", "password123", "admin", "letmein", "welcome",
    "monkey", "dragon", "master", "qwerty", "login", "password1",
    "123456789", "12345678", "abc123", "111111", "admin123", "root",
    "toor", "pass", "test", "guest", "master123", "changeme",
    "123123", "1234567890", "password!", "Password1", "Password123",
]


@mcp.tool()
async def identify_hash(hash_value: str) -> str:
    """
    Identify the type of a hash.

    Args:
        hash_value: Hash string to identify

    Returns:
        JSON with possible hash types and hashcat modes
    """
    hash_value = hash_value.strip()
    matches = []

    for hash_type, config in HASH_PATTERNS.items():
        if re.match(config["regex"], hash_value):
            matches.append({
                "type": hash_type,
                "description": config["description"],
                "hashcat_mode": config["hashcat_mode"],
                "confidence": "high" if config.get("length") == len(hash_value) else "medium",
            })

    # Special case: distinguish MD5 vs NTLM (both 32 hex chars)
    if len(hash_value) == 32 and re.match(r"^[a-fA-F0-9]{32}$", hash_value):
        # Check if it's uppercase (more likely NTLM from Windows)
        if hash_value == hash_value.upper():
            for match in matches:
                if match["type"] == "ntlm":
                    match["confidence"] = "high"
                elif match["type"] == "md5":
                    match["confidence"] = "medium"

    if not matches:
        # Try to provide guidance based on length
        length_hints = {
            32: "Possibly MD5, NTLM, or LM hash",
            40: "Possibly SHA-1 or MySQL hash",
            64: "Possibly SHA-256 or other 256-bit hash",
            128: "Possibly SHA-512 or other 512-bit hash",
        }
        hint = length_hints.get(len(hash_value), f"Unknown hash type (length: {len(hash_value)})")
        return json.dumps({
            "hash": hash_value,
            "matches": [],
            "hint": hint,
        }, indent=2)

    return json.dumps({
        "hash": hash_value,
        "length": len(hash_value),
        "matches": matches,
        "recommended_mode": matches[0]["hashcat_mode"] if matches else None,
    }, indent=2)


@mcp.tool()
async def hash_string(
    plaintext: str,
    algorithm: str = "sha256",
    iterations: int = 1,
    salt: Optional[str] = None,
) -> str:
    """
    Hash a string with specified algorithm.

    Args:
        plaintext: String to hash
        algorithm: Hash algorithm (md5, sha1, sha256, sha512, ntlm)
        iterations: Number of iterations (for key stretching)
        salt: Optional salt to prepend

    Returns:
        JSON with hash result
    """
    try:
        data = plaintext.encode()
        if salt:
            data = salt.encode() + data

        if algorithm.lower() == "ntlm":
            # NTLM uses MD4 of UTF-16LE encoded password
            import struct
            ntlm_hash = hashlib.new("md4", plaintext.encode("utf-16le")).hexdigest()
            return json.dumps({
                "plaintext": plaintext,
                "algorithm": "ntlm",
                "hash": ntlm_hash.upper(),
            }, indent=2)

        hash_func = getattr(hashlib, algorithm.lower(), None)
        if not hash_func:
            return json.dumps({"error": f"Unknown algorithm: {algorithm}"})

        result = hash_func(data).hexdigest()

        for _ in range(iterations - 1):
            result = hash_func(result.encode()).hexdigest()

        return json.dumps({
            "plaintext": plaintext,
            "algorithm": algorithm,
            "salt": salt,
            "iterations": iterations,
            "hash": result,
        }, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def crack_hash(
    hash_value: str,
    hash_type: Optional[str] = None,
    wordlist: str = "common",
    timeout: int = 60,
) -> str:
    """
    Attempt to crack a hash using wordlist or hashcat.

    Args:
        hash_value: Hash to crack
        hash_type: Hash type (auto-detect if not specified)
        wordlist: Wordlist to use (common, extended, or path to file)
        timeout: Timeout in seconds

    Returns:
        JSON with cracking result
    """
    hash_value = hash_value.strip()

    # Auto-detect hash type
    if not hash_type:
        id_result = await identify_hash(hash_value)
        id_data = json.loads(id_result)
        if id_data.get("matches"):
            hash_type = id_data["matches"][0]["type"]
        else:
            return json.dumps({
                "error": "Could not identify hash type",
                "hash": hash_value,
            })

    # Get hash config
    config = HASH_PATTERNS.get(hash_type, {})

    # Try common passwords first
    passwords_to_try = COMMON_PASSWORDS.copy()
    if wordlist == "extended":
        passwords_to_try.extend([
            f"Password{i}" for i in range(1, 100)
        ] + [
            f"Admin{i}" for i in range(1, 100)
        ] + [
            f"{word}!" for word in COMMON_PASSWORDS
        ] + [
            f"{word}123" for word in COMMON_PASSWORDS
        ])

    # Quick dictionary attack
    for password in passwords_to_try:
        if hash_type == "ntlm":
            test_hash = hashlib.new("md4", password.encode("utf-16le")).hexdigest().upper()
            if test_hash.upper() == hash_value.upper():
                return json.dumps({
                    "status": "cracked",
                    "hash": hash_value,
                    "plaintext": password,
                    "method": "dictionary",
                }, indent=2)
        elif hash_type in ["md5", "sha1", "sha256", "sha512"]:
            hash_func = getattr(hashlib, hash_type)
            test_hash = hash_func(password.encode()).hexdigest()
            if test_hash.lower() == hash_value.lower():
                return json.dumps({
                    "status": "cracked",
                    "hash": hash_value,
                    "plaintext": password,
                    "method": "dictionary",
                }, indent=2)

    # Try hashcat if available
    if shutil.which("hashcat") and config.get("hashcat_mode") is not None:
        result = await _hashcat_crack(hash_value, config["hashcat_mode"], timeout)
        if result:
            return json.dumps(result, indent=2)

    return json.dumps({
        "status": "not_cracked",
        "hash": hash_value,
        "hash_type": hash_type,
        "attempts": len(passwords_to_try),
        "suggestion": f"hashcat -m {config.get('hashcat_mode', '?')} -a 0 hash.txt wordlist.txt",
    }, indent=2)


async def _hashcat_crack(hash_value: str, mode: int, timeout: int) -> Optional[dict]:
    """Use hashcat for cracking."""
    import tempfile

    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(hash_value)
            hash_file = f.name

        cmd = [
            "hashcat",
            "-m", str(mode),
            "-a", "3",  # Brute force
            hash_file,
            "?a?a?a?a?a?a",  # 6-char mask
            "--potfile-disable",
            "-O",  # Optimized kernels
        ]

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            await asyncio.wait_for(process.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            process.kill()

        # Check potfile for results
        cmd_show = ["hashcat", "-m", str(mode), hash_file, "--show"]
        process = await asyncio.create_subprocess_exec(
            *cmd_show,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await process.communicate()

        output = stdout.decode().strip()
        if ":" in output:
            parts = output.split(":")
            return {
                "status": "cracked",
                "hash": hash_value,
                "plaintext": parts[-1],
                "method": "hashcat",
            }

    except Exception:
        pass

    return None


@mcp.tool()
async def jwt_decode(token: str) -> str:
    """
    Decode and analyze a JWT token.

    Args:
        token: JWT token to decode

    Returns:
        JSON with decoded header, payload, and security analysis
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return json.dumps({"error": "Invalid JWT format (expected 3 parts)"})

        # Decode header and payload
        def decode_part(part):
            # Add padding if needed
            padding = 4 - len(part) % 4
            if padding != 4:
                part += "=" * padding
            return json.loads(base64.urlsafe_b64decode(part))

        header = decode_part(parts[0])
        payload = decode_part(parts[1])

        # Security analysis
        vulnerabilities = []

        # Check algorithm
        alg = header.get("alg", "").upper()
        if alg == "NONE":
            vulnerabilities.append({
                "issue": "Algorithm None",
                "severity": "critical",
                "description": "JWT uses 'none' algorithm - signature not verified",
            })
        elif alg in ["HS256", "HS384", "HS512"]:
            vulnerabilities.append({
                "issue": "Symmetric Algorithm",
                "severity": "info",
                "description": "Uses HMAC - if secret is weak, token can be forged",
            })

        # Check expiration
        exp = payload.get("exp")
        if exp:
            exp_time = datetime.fromtimestamp(exp)
            if exp_time < datetime.now():
                vulnerabilities.append({
                    "issue": "Expired Token",
                    "severity": "medium",
                    "description": f"Token expired at {exp_time.isoformat()}",
                })
        else:
            vulnerabilities.append({
                "issue": "No Expiration",
                "severity": "medium",
                "description": "Token has no expiration claim",
            })

        # Check for sensitive data
        sensitive_keys = ["password", "secret", "key", "token", "api_key", "credit_card"]
        for key in payload.keys():
            if any(s in key.lower() for s in sensitive_keys):
                vulnerabilities.append({
                    "issue": "Sensitive Data in Payload",
                    "severity": "high",
                    "description": f"Potentially sensitive key found: {key}",
                })

        return json.dumps({
            "header": header,
            "payload": payload,
            "signature": parts[2][:20] + "..." if len(parts[2]) > 20 else parts[2],
            "algorithm": alg,
            "expiration": datetime.fromtimestamp(exp).isoformat() if exp else None,
            "vulnerabilities": vulnerabilities,
            "claims": list(payload.keys()),
        }, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def jwt_forge(
    payload: str,
    secret: str = "",
    algorithm: str = "HS256",
    expiry_hours: int = 24,
) -> str:
    """
    Forge a JWT token with custom payload.

    Args:
        payload: JSON string of payload claims
        secret: Secret key for signing (empty for 'none' algorithm attack)
        algorithm: Algorithm to use (HS256, HS384, HS512, none)
        expiry_hours: Hours until expiration

    Returns:
        JSON with forged JWT token
    """
    try:
        payload_data = json.loads(payload)
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON payload"})

    # Add standard claims if not present
    now = datetime.utcnow()
    if "iat" not in payload_data:
        payload_data["iat"] = int(now.timestamp())
    if "exp" not in payload_data:
        payload_data["exp"] = int((now + timedelta(hours=expiry_hours)).timestamp())

    # Build header
    header = {"alg": algorithm, "typ": "JWT"}

    # Encode parts
    def encode_part(data):
        json_str = json.dumps(data, separators=(",", ":"))
        return base64.urlsafe_b64encode(json_str.encode()).rstrip(b"=").decode()

    header_b64 = encode_part(header)
    payload_b64 = encode_part(payload_data)

    # Create signature
    if algorithm.lower() == "none":
        signature = ""
        token = f"{header_b64}.{payload_b64}."
    else:
        message = f"{header_b64}.{payload_b64}"

        if algorithm == "HS256":
            sig = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
        elif algorithm == "HS384":
            sig = hmac.new(secret.encode(), message.encode(), hashlib.sha384).digest()
        elif algorithm == "HS512":
            sig = hmac.new(secret.encode(), message.encode(), hashlib.sha512).digest()
        else:
            return json.dumps({"error": f"Unsupported algorithm: {algorithm}"})

        signature = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        token = f"{header_b64}.{payload_b64}.{signature}"

    return json.dumps({
        "token": token,
        "header": header,
        "payload": payload_data,
        "algorithm": algorithm,
        "secret_used": bool(secret),
        "expires": datetime.fromtimestamp(payload_data["exp"]).isoformat(),
    }, indent=2)


@mcp.tool()
async def jwt_crack_secret(
    token: str,
    wordlist: str = "common",
    timeout: int = 30,
) -> str:
    """
    Attempt to crack a JWT secret key.

    Args:
        token: JWT token to crack
        wordlist: Wordlist type (common, extended) or comma-separated secrets
        timeout: Timeout in seconds

    Returns:
        JSON with cracking result
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return json.dumps({"error": "Invalid JWT format"})

        # Decode header to get algorithm
        padding = 4 - len(parts[0]) % 4
        if padding != 4:
            parts[0] += "=" * padding
        header = json.loads(base64.urlsafe_b64decode(parts[0]))

        alg = header.get("alg", "").upper()
        if alg not in ["HS256", "HS384", "HS512"]:
            return json.dumps({
                "error": f"Cannot crack {alg} algorithm",
                "note": "Only HMAC algorithms (HS256/384/512) can be cracked",
            })

        # Get hash function
        hash_funcs = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }
        hash_func = hash_funcs[alg]

        # Prepare signature for comparison
        message = f"{parts[0]}.{parts[1]}"

        # Add padding to signature
        sig_padding = 4 - len(parts[2]) % 4
        if sig_padding != 4:
            parts[2] += "=" * sig_padding
        target_sig = base64.urlsafe_b64decode(parts[2])

        # Build wordlist
        secrets_to_try = [
            "secret", "password", "jwt_secret", "jwt-secret", "key",
            "private_key", "signing_key", "auth_secret", "token_secret",
            "supersecret", "mysecret", "secretkey", "secret123",
        ]

        if wordlist == "extended":
            secrets_to_try.extend([
                f"secret{i}" for i in range(1, 100)
            ] + [
                f"key{i}" for i in range(1, 100)
            ] + [
                "development", "production", "staging", "test",
                "dev_secret", "prod_secret", "api_secret",
            ])
        elif wordlist not in ["common", "extended"]:
            secrets_to_try = [s.strip() for s in wordlist.split(",")]

        # Attempt cracking
        start_time = asyncio.get_event_loop().time()

        for secret in secrets_to_try:
            if asyncio.get_event_loop().time() - start_time > timeout:
                break

            test_sig = hmac.new(secret.encode(), message.encode(), hash_func).digest()
            if test_sig == target_sig:
                return json.dumps({
                    "status": "cracked",
                    "secret": secret,
                    "algorithm": alg,
                    "attempts": secrets_to_try.index(secret) + 1,
                }, indent=2)

        return json.dumps({
            "status": "not_cracked",
            "algorithm": alg,
            "attempts": len(secrets_to_try),
            "suggestion": "Try a larger wordlist or use hashcat with JWT mode",
        }, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def generate_password_list(
    base_words: str,
    rules: str = "common",
    limit: int = 1000,
) -> str:
    """
    Generate a password list based on words and mutation rules.

    Args:
        base_words: Comma-separated base words
        rules: Rule set (common, leet, years, symbols, all)
        limit: Maximum passwords to generate

    Returns:
        JSON with generated password list
    """
    words = [w.strip() for w in base_words.split(",")]
    passwords = set()

    # Add base words
    for word in words:
        passwords.add(word)
        passwords.add(word.lower())
        passwords.add(word.upper())
        passwords.add(word.capitalize())

    # Common mutations
    if rules in ["common", "all"]:
        for word in words:
            # Numbers
            for i in range(10):
                passwords.add(f"{word}{i}")
                passwords.add(f"{i}{word}")
            for i in range(100):
                passwords.add(f"{word}{i:02d}")
            passwords.add(f"{word}123")
            passwords.add(f"{word}1234")
            passwords.add(f"123{word}")

    # Leet speak
    if rules in ["leet", "all"]:
        leet_map = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}
        for word in words:
            leet = word.lower()
            for char, replacement in leet_map.items():
                leet = leet.replace(char, replacement)
            passwords.add(leet)
            passwords.add(leet.upper())

    # Years
    if rules in ["years", "all"]:
        current_year = datetime.now().year
        for word in words:
            for year in range(current_year - 30, current_year + 2):
                passwords.add(f"{word}{year}")
                passwords.add(f"{year}{word}")
                passwords.add(f"{word}{str(year)[-2:]}")

    # Symbols
    if rules in ["symbols", "all"]:
        symbols = ["!", "@", "#", "$", "!", "?", "*"]
        for word in words:
            for sym in symbols:
                passwords.add(f"{word}{sym}")
                passwords.add(f"{sym}{word}")
                passwords.add(f"{word}{sym}{sym}")

    # Limit and sort
    password_list = sorted(list(passwords))[:limit]

    return json.dumps({
        "base_words": words,
        "rules_applied": rules,
        "count": len(password_list),
        "passwords": password_list,
    }, indent=2)


@mcp.tool()
async def credential_spray(
    usernames: str,
    passwords: str,
    service: str = "ssh",
    target: Optional[str] = None,
    dry_run: bool = True,
) -> str:
    """
    Generate credential spray attack commands (dry run by default).

    Args:
        usernames: Comma-separated usernames or 'common'
        passwords: Comma-separated passwords or 'common'
        service: Target service (ssh, ftp, http-basic, rdp)
        target: Target host (required for execution)
        dry_run: If True, only generate commands

    Returns:
        JSON with spray commands or results
    """
    # Parse usernames
    if usernames == "common":
        user_list = ["admin", "root", "administrator", "user", "guest", "test"]
    else:
        user_list = [u.strip() for u in usernames.split(",")]

    # Parse passwords
    if passwords == "common":
        pass_list = COMMON_PASSWORDS[:20]
    else:
        pass_list = [p.strip() for p in passwords.split(",")]

    # Generate combinations
    combinations = [(u, p) for u in user_list for p in pass_list]

    # Generate commands based on service
    commands = []
    if service == "ssh":
        for user, password in combinations[:50]:
            commands.append(f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no {user}@TARGET")
        tool_suggestion = f"hydra -L users.txt -P passwords.txt TARGET ssh"

    elif service == "ftp":
        for user, password in combinations[:50]:
            commands.append(f"lftp -u {user},{password} TARGET")
        tool_suggestion = f"hydra -L users.txt -P passwords.txt TARGET ftp"

    elif service == "http-basic":
        for user, password in combinations[:50]:
            commands.append(f"curl -u '{user}:{password}' http://TARGET/")
        tool_suggestion = f"hydra -L users.txt -P passwords.txt TARGET http-get /"

    elif service == "rdp":
        tool_suggestion = f"crowbar -b rdp -s TARGET/32 -U users.txt -C passwords.txt"
        commands.append("# Use crowbar or hydra for RDP")

    else:
        return json.dumps({"error": f"Unknown service: {service}"})

    return json.dumps({
        "service": service,
        "usernames": user_list,
        "passwords": pass_list[:10] + ["..."] if len(pass_list) > 10 else pass_list,
        "total_combinations": len(combinations),
        "sample_commands": commands[:10],
        "tool_suggestion": tool_suggestion,
        "dry_run": dry_run,
        "warning": "Only use against authorized targets",
    }, indent=2)


@mcp.tool()
async def encode_decode(
    data: str,
    operation: str = "encode",
    encoding: str = "base64",
    key: Optional[str] = None,
) -> str:
    """
    Encode or decode data using various schemes.

    Args:
        data: Data to encode/decode
        operation: Operation (encode, decode)
        encoding: Encoding type (base64, base64url, hex, url, rot13, xor)
        key: Key for XOR encoding

    Returns:
        JSON with encoded/decoded result
    """
    import urllib.parse

    try:
        result = None

        if encoding == "base64":
            if operation == "encode":
                result = base64.b64encode(data.encode()).decode()
            else:
                result = base64.b64decode(data).decode()

        elif encoding == "base64url":
            if operation == "encode":
                result = base64.urlsafe_b64encode(data.encode()).decode()
            else:
                # Add padding if needed
                padding = 4 - len(data) % 4
                if padding != 4:
                    data += "=" * padding
                result = base64.urlsafe_b64decode(data).decode()

        elif encoding == "hex":
            if operation == "encode":
                result = data.encode().hex()
            else:
                result = bytes.fromhex(data).decode()

        elif encoding == "url":
            if operation == "encode":
                result = urllib.parse.quote(data)
            else:
                result = urllib.parse.unquote(data)

        elif encoding == "rot13":
            result = data.translate(str.maketrans(
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
            ))

        elif encoding == "xor":
            if not key:
                return json.dumps({"error": "XOR encoding requires a key"})
            key_bytes = key.encode()
            data_bytes = data.encode() if operation == "encode" else bytes.fromhex(data)
            result_bytes = bytes(
                data_bytes[i] ^ key_bytes[i % len(key_bytes)]
                for i in range(len(data_bytes))
            )
            if operation == "encode":
                result = result_bytes.hex()
            else:
                result = result_bytes.decode()

        else:
            return json.dumps({"error": f"Unknown encoding: {encoding}"})

        return json.dumps({
            "input": data[:100] + "..." if len(data) > 100 else data,
            "operation": operation,
            "encoding": encoding,
            "result": result,
        }, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def generate_secure_token(
    length: int = 32,
    format: str = "hex",
    count: int = 1,
) -> str:
    """
    Generate cryptographically secure random tokens.

    Args:
        length: Token length (in bytes for hex, characters for others)
        format: Token format (hex, base64, alphanumeric, uuid)
        count: Number of tokens to generate

    Returns:
        JSON with generated tokens
    """
    import uuid

    tokens = []

    for _ in range(min(count, 100)):
        if format == "hex":
            token = secrets.token_hex(length)
        elif format == "base64":
            token = secrets.token_urlsafe(length)
        elif format == "alphanumeric":
            alphabet = string.ascii_letters + string.digits
            token = "".join(secrets.choice(alphabet) for _ in range(length))
        elif format == "uuid":
            token = str(uuid.uuid4())
        else:
            return json.dumps({"error": f"Unknown format: {format}"})

        tokens.append(token)

    return json.dumps({
        "format": format,
        "length": length,
        "count": len(tokens),
        "tokens": tokens if count > 1 else tokens[0],
    }, indent=2)


@mcp.tool()
async def analyze_password_strength(
    password: str,
) -> str:
    """
    Analyze password strength and provide recommendations.

    Args:
        password: Password to analyze

    Returns:
        JSON with strength analysis and recommendations
    """
    analysis = {
        "password_length": len(password),
        "character_sets": [],
        "patterns_found": [],
        "score": 0,
        "strength": "",
        "recommendations": [],
    }

    # Check character sets
    if re.search(r"[a-z]", password):
        analysis["character_sets"].append("lowercase")
        analysis["score"] += 10

    if re.search(r"[A-Z]", password):
        analysis["character_sets"].append("uppercase")
        analysis["score"] += 10

    if re.search(r"\d", password):
        analysis["character_sets"].append("digits")
        analysis["score"] += 10

    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        analysis["character_sets"].append("special")
        analysis["score"] += 15

    # Length scoring
    if len(password) >= 8:
        analysis["score"] += 10
    if len(password) >= 12:
        analysis["score"] += 15
    if len(password) >= 16:
        analysis["score"] += 15

    # Check for common patterns
    if password.lower() in COMMON_PASSWORDS:
        analysis["patterns_found"].append("common_password")
        analysis["score"] -= 50

    if re.search(r"(.)\1{2,}", password):
        analysis["patterns_found"].append("repeated_chars")
        analysis["score"] -= 10

    if re.search(r"(012|123|234|345|456|567|678|789|890)", password):
        analysis["patterns_found"].append("sequential_numbers")
        analysis["score"] -= 10

    if re.search(r"(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)", password.lower()):
        analysis["patterns_found"].append("sequential_letters")
        analysis["score"] -= 10

    if re.search(r"(qwerty|asdf|zxcv)", password.lower()):
        analysis["patterns_found"].append("keyboard_pattern")
        analysis["score"] -= 15

    # Determine strength
    if analysis["score"] >= 60:
        analysis["strength"] = "strong"
    elif analysis["score"] >= 40:
        analysis["strength"] = "moderate"
    elif analysis["score"] >= 20:
        analysis["strength"] = "weak"
    else:
        analysis["strength"] = "very_weak"

    # Recommendations
    if len(password) < 12:
        analysis["recommendations"].append("Increase length to at least 12 characters")
    if "uppercase" not in analysis["character_sets"]:
        analysis["recommendations"].append("Add uppercase letters")
    if "special" not in analysis["character_sets"]:
        analysis["recommendations"].append("Add special characters")
    if analysis["patterns_found"]:
        analysis["recommendations"].append("Avoid common patterns and sequences")

    analysis["score"] = max(0, min(100, analysis["score"]))

    return json.dumps(analysis, indent=2)


if __name__ == "__main__":
    from fragbench_mcp.servers.server_entrypoint import parse_server_args, run_mcp_http_server

    args = parse_server_args(
        description="Crypto MCP Server",
        default_port=8029,
        default_name="crypto",
    )
    run_mcp_http_server(mcp, args=args)
