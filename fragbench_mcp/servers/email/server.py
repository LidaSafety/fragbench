#!/usr/bin/env python3
"""Simulated email MCP server.

Provides three tools so attack fragments with a *dispatch* / *send* role have
a concrete tool surface to call against — without any real SMTP delivery.

Tools:
    compose_email(subject, body, to, attachments=None)
        Persist an .eml-like draft under /workspace/outbox and return its id.
    send_email(draft_id_or_path, to=None, from_addr=None, subject=None)
        Append a record to /workspace/outbox/sent.jsonl. Always returns
        ``mode="simulated"`` — no network traffic.
    list_outbox()
        Return summaries of every draft and sent record on disk.

The on-disk layout under /workspace/outbox/ mirrors what an attacker would
see: one .eml per draft + a sent.jsonl audit trail. The judge uses these
tool calls to certify dispatch fragments.
"""

from __future__ import annotations

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "_shared"))

import json
import re
import uuid
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Optional

from fastmcp import FastMCP

mcp = FastMCP("email")

OUTBOX_ROOT = Path(os.environ.get("EMAIL_OUTBOX_DIR", "/workspace/outbox"))
SENT_LOG = OUTBOX_ROOT / "sent.jsonl"


def _ensure_outbox() -> None:
    OUTBOX_ROOT.mkdir(parents=True, exist_ok=True)


def _safe_id(value: str | None = None) -> str:
    if value:
        cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_")
        if cleaned:
            return cleaned[:64]
    return uuid.uuid4().hex[:12]


def _resolve_draft(path_or_id: str) -> Path | None:
    candidate = Path(path_or_id)
    if candidate.is_absolute() and candidate.exists():
        return candidate
    relative = OUTBOX_ROOT / path_or_id
    if relative.exists():
        return relative
    if not path_or_id.endswith(".eml"):
        with_ext = OUTBOX_ROOT / f"{path_or_id}.eml"
        if with_ext.exists():
            return with_ext
    return None


@mcp.tool()
def compose_email(
    subject: str,
    body: str,
    to: str,
    attachments: Optional[list[str]] = None,
    from_addr: Optional[str] = None,
    draft_id: Optional[str] = None,
) -> str:
    """Persist an email draft to /workspace/outbox/<draft_id>.eml.

    Returns a JSON string with ``draft_id``, ``path`` and a small preview.
    """
    _ensure_outbox()
    draft_id = _safe_id(draft_id or subject or to)
    draft_path = OUTBOX_ROOT / f"{draft_id}.eml"

    msg = EmailMessage()
    msg["Subject"] = subject or "(no subject)"
    msg["To"] = to or ""
    msg["From"] = from_addr or "agent@example.local"
    msg["Date"] = datetime.now(timezone.utc).isoformat()
    msg.set_content(body or "")

    for ref in attachments or []:
        try:
            ref_path = Path(ref).expanduser()
            if ref_path.is_absolute() and ref_path.exists():
                data = ref_path.read_bytes()
            else:
                data = (Path("/workspace") / ref).read_bytes()
            msg.add_attachment(
                data, maintype="application", subtype="octet-stream", filename=Path(ref).name
            )
        except Exception:  # noqa: BLE001
            # Attachment lookup failures are non-fatal in simulated mode.
            continue

    draft_path.write_bytes(bytes(msg))
    return json.dumps(
        {
            "success": True,
            "mode": "simulated",
            "draft_id": draft_id,
            "path": str(draft_path),
            "to": to,
            "subject": subject or "(no subject)",
            "bytes": draft_path.stat().st_size,
            "attachments": list(attachments or []),
        }
    )


@mcp.tool()
def send_email(
    draft_id_or_path: str,
    to: Optional[str] = None,
    from_addr: Optional[str] = None,
    subject: Optional[str] = None,
) -> str:
    """Mark a draft as 'sent' by appending to /workspace/outbox/sent.jsonl.

    No SMTP traffic is ever generated. Returns ``mode="simulated"``.
    """
    _ensure_outbox()
    record: dict[str, Any] = {
        "success": True,
        "mode": "simulated",
        "message_id": uuid.uuid4().hex,
        "sent_at": datetime.now(timezone.utc).isoformat(),
        "to": to,
        "from": from_addr,
        "subject": subject,
        "draft_ref": draft_id_or_path,
    }

    draft_path = _resolve_draft(draft_id_or_path) if draft_id_or_path else None
    if draft_path is not None:
        record["draft_path"] = str(draft_path)
        record["draft_bytes"] = draft_path.stat().st_size
        # Best-effort: read recipients/subject from the .eml if not given.
        try:
            from email import message_from_bytes
            parsed = message_from_bytes(draft_path.read_bytes())
            record.setdefault("to", parsed.get("To"))
            record.setdefault("from", parsed.get("From"))
            record.setdefault("subject", parsed.get("Subject"))
        except Exception:  # noqa: BLE001
            pass
    elif draft_id_or_path:
        record["warning"] = f"draft '{draft_id_or_path}' not found; recording send anyway"

    with SENT_LOG.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, default=str) + "\n")

    return json.dumps(record, default=str)


@mcp.tool()
def list_outbox() -> str:
    """List every draft (.eml) and every sent record."""
    _ensure_outbox()
    drafts: list[dict[str, Any]] = []
    for path in sorted(OUTBOX_ROOT.glob("*.eml")):
        try:
            stat = path.stat()
        except OSError:
            continue
        drafts.append(
            {
                "draft_id": path.stem,
                "path": str(path),
                "bytes": stat.st_size,
                "modified_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            }
        )

    sent: list[dict[str, Any]] = []
    if SENT_LOG.exists():
        for line in SENT_LOG.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                sent.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return json.dumps(
        {
            "success": True,
            "outbox_dir": str(OUTBOX_ROOT),
            "drafts": drafts,
            "sent": sent,
            "draft_count": len(drafts),
            "sent_count": len(sent),
        },
        default=str,
    )


if __name__ == "__main__":
    from server_entrypoint import parse_server_args, run_mcp_http_server
    args = parse_server_args(description="Email MCP server (simulated)", default_port=8038)
    _ensure_outbox()
    run_mcp_http_server(mcp, args=args)
