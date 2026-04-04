"""
Thin async client that posts audit events to the MCP Audit Server.
Fire-and-forget — audit failures NEVER block the proxied response.
"""

import logging
import asyncio
from typing import Optional, Any

import httpx

from .config import gateway_settings

logger = logging.getLogger("mcp_gateway.audit")


async def log_tool_call(
    client_id:      str,
    user_id:        Optional[str],
    mcp_server_id:  str,
    tool_name:      str,
    tool_input:     Optional[Any],
    tool_output:    Optional[Any],
    outcome:        str,
    duration_ms:    float,
    severity:       str = "info",
    error_message:  Optional[str] = None,
    trace_id:       Optional[str] = None,
    session_id:     Optional[str] = None,
    caller_ip:      Optional[str] = None,
    token_scopes:   Optional[list] = None,
    policy_decision: Optional[str] = None,
    agent_name:     Optional[str] = None,
):
    payload = {
        "client_id":      client_id,
        "user_id":        user_id,
        "agent_name":     agent_name,
        "mcp_server_id":  mcp_server_id,
        "tool_name":      tool_name,
        "tool_input":     tool_input,
        "tool_output":    tool_output,
        "outcome":        outcome,
        "duration_ms":    round(duration_ms, 2),
        "severity":       severity,
        "error_message":  error_message,
        "trace_id":       trace_id,
        "session_id":     session_id,
        "caller_ip":      caller_ip,
        "token_scopes":   token_scopes,
        "policy_decision": policy_decision,
    }

    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            await client.post(
                f"{gateway_settings.AUDIT_SERVER_URL}/events",
                json=payload,
                headers={"x-audit-api-key": gateway_settings.AUDIT_INGEST_KEY},
            )
    except Exception as exc:
        # Never let audit failure surface to the caller
        logger.error("Audit log failed for %s/%s: %s", mcp_server_id, tool_name, exc)
