"""Posts secret access events to the MCP Audit Server."""

import logging
from typing import Optional
import httpx
from .config import secrets_settings

logger = logging.getLogger("mcp_secrets.audit")


async def log_secret_access(
    client_id:    str,
    secret_name:  str,
    action:       str,   # "lease_issued", "lease_revoked", "access_denied", "rotated"
    outcome:      str,   # "success", "denied", "error"
    user_id:      Optional[str] = None,
    trace_id:     Optional[str] = None,
    caller_ip:    Optional[str] = None,
    error_message: Optional[str] = None,
    lease_id:     Optional[str] = None,
):
    payload = {
        "client_id":     client_id,
        "user_id":       user_id,
        "mcp_server_id": "secrets-server",
        "tool_name":     action,
        "tool_input":    {"secret_name": secret_name, "lease_id": lease_id},
        "tool_output":   None,   # Never log secret values to audit
        "outcome":       outcome,
        "severity":      "critical" if outcome == "denied" else "info",
        "error_message": error_message,
        "trace_id":      trace_id,
        "caller_ip":     caller_ip,
    }
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            await client.post(
                f"{secrets_settings.AUDIT_SERVER_URL}/events",
                json=payload,
                headers={"x-audit-api-key": secrets_settings.AUDIT_INGEST_KEY},
            )
    except Exception as exc:
        logger.error("Audit log failed for secret access %s/%s: %s", client_id, secret_name, exc)
