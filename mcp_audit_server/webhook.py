import json
import logging
from typing import Optional

import httpx

from .config import audit_settings
from .models import AuditEvent

logger = logging.getLogger("mcp_audit.webhook")


def _event_to_dict(event: AuditEvent) -> dict:
    return {
        "event_id":       event.event_id,
        "created_at":     event.created_at.isoformat(),
        "client_id":      event.client_id,
        "user_id":        event.user_id,
        "agent_name":     event.agent_name,
        "mcp_server_id":  event.mcp_server_id,
        "tool_name":      event.tool_name,
        "outcome":        event.outcome,
        "severity":       event.severity,
        "error_message":  event.error_message,
        "duration_ms":    event.duration_ms,
        "trace_id":       event.trace_id,
        "session_id":     event.session_id,
        "caller_ip":      event.caller_ip,
        "policy_decision": event.policy_decision,
        # Tool I/O intentionally omitted from webhook — may contain PII.
        # Compliance systems should query the audit server directly for full records.
    }


async def forward_to_siem(event: AuditEvent):
    """
    Fire-and-forget async webhook to SIEM (Splunk, Datadog, etc.).
    Failures are logged but never surface as errors to the caller.
    """
    if not audit_settings.SIEM_WEBHOOK_URL:
        return

    headers = {"Content-Type": "application/json"}
    if audit_settings.SIEM_WEBHOOK_API_KEY:
        headers["Authorization"] = f"Bearer {audit_settings.SIEM_WEBHOOK_API_KEY}"

    payload = _event_to_dict(event)

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                audit_settings.SIEM_WEBHOOK_URL,
                content=json.dumps(payload),
                headers=headers,
            )
            if resp.status_code >= 400:
                logger.warning(
                    "SIEM webhook returned %s for event %s",
                    resp.status_code,
                    event.event_id,
                )
    except Exception as exc:
        logger.error("SIEM webhook failed for event %s: %s", event.event_id, exc)
