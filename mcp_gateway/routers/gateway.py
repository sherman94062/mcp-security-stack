"""
Main gateway routing endpoint.

Request flow:
  Agent → POST /gateway/{server_id}/tools/{tool_name}
    1. Extract + introspect bearer token → TokenContext
    2. Evaluate policy → PolicyDecision
    3. If denied: log + return 403
    4. Proxy to backend MCP server
    5. Log to audit server (fire-and-forget)
    6. Return proxied response with rate-limit headers
"""

import asyncio
import time
import uuid
import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Header
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from ..storage import get_db, get_server
from ..policy import evaluate
from ..auth import introspect_token
from ..proxy import forward_request
from ..audit_client import log_tool_call

logger = logging.getLogger("mcp_gateway.router")

router = APIRouter(prefix="/gateway", tags=["Gateway"])


@router.post("/{server_id}/tools/{tool_name}")
async def proxy_tool_call(
    server_id:     str,
    tool_name:     str,
    request:       Request,
    authorization: Optional[str] = Header(default=None),
    x_trace_id:    Optional[str] = Header(default=None),
    x_session_id:  Optional[str] = Header(default=None),
    db:            AsyncSession = Depends(get_db),
):
    """
    Single gateway entry point for all MCP tool calls.

    Agents call:
        POST /gateway/{server_id}/tools/{tool_name}
        Authorization: Bearer <token>
        Content-Type: application/json

        { ...tool_input... }

    The gateway validates, enforces policy, proxies, and logs.
    """

    # ── Generate trace ID if not provided ────────────────────────────────────
    trace_id = x_trace_id or str(uuid.uuid4())
    caller_ip = request.client.host if request.client else None
    start_ms = time.monotonic() * 1000

    # ── Parse request body ────────────────────────────────────────────────────
    try:
        tool_input = await request.json()
    except Exception:
        tool_input = {}

    # ── 1. Token introspection ────────────────────────────────────────────────
    bearer = None
    if authorization and authorization.startswith("Bearer "):
        bearer = authorization.removeprefix("Bearer ").strip()

    token_ctx = await introspect_token(bearer or "")

    if not token_ctx.active:
        asyncio.create_task(log_tool_call(
            client_id="unknown", user_id=None,
            mcp_server_id=server_id, tool_name=tool_name,
            tool_input=tool_input, tool_output=None,
            outcome="denied", duration_ms=_elapsed(start_ms),
            severity="critical",
            error_message="Invalid or missing bearer token",
            trace_id=trace_id, session_id=x_session_id,
            caller_ip=caller_ip, policy_decision="token_invalid",
        ))
        return JSONResponse(
            status_code=401,
            content={"error": "invalid_token", "detail": "Bearer token is missing or invalid"},
            headers={"x-trace-id": trace_id},
        )

    client_id = token_ctx.client_id

    # ── 2. Policy evaluation ──────────────────────────────────────────────────
    decision = await evaluate(db, client_id, server_id, tool_name)

    if not decision.allowed:
        severity = "critical" if decision.rate_limited else "warning"
        asyncio.create_task(log_tool_call(
            client_id=client_id, user_id=token_ctx.user_id,
            mcp_server_id=server_id, tool_name=tool_name,
            tool_input=tool_input, tool_output=None,
            outcome="denied", duration_ms=_elapsed(start_ms),
            severity=severity,
            error_message=decision.reason,
            trace_id=trace_id, session_id=x_session_id,
            caller_ip=caller_ip,
            token_scopes=token_ctx.scopes,
            policy_decision=decision.reason,
        ))

        status = 429 if decision.rate_limited else 403
        headers = {"x-trace-id": trace_id}
        if decision.remaining_rpm is not None:
            headers["x-ratelimit-remaining-rpm"] = str(decision.remaining_rpm)
        if decision.remaining_rpd is not None:
            headers["x-ratelimit-remaining-rpd"] = str(decision.remaining_rpd)

        return JSONResponse(
            status_code=status,
            content={"error": "forbidden", "detail": decision.reason},
            headers=headers,
        )

    # ── 3. Load backend server ────────────────────────────────────────────────
    server = await get_server(db, server_id)
    # (Already validated in policy.evaluate, but safety check)
    if not server:
        return JSONResponse(status_code=404, content={"error": "server_not_found"})

    # ── 4. Proxy to backend ───────────────────────────────────────────────────
    status_code, response_body, duration_ms = await forward_request(
        base_url=server.base_url,
        tool_name=tool_name,
        tool_input=tool_input,
        headers=dict(request.headers),
        trace_id=trace_id,
    )

    outcome = (
        "success" if status_code < 400
        else "error"   if status_code >= 500
        else "failure"
    )
    severity = "critical" if status_code >= 500 else "info"

    # ── 5. Audit log (non-blocking) ───────────────────────────────────────────
    asyncio.create_task(log_tool_call(
        client_id=client_id, user_id=token_ctx.user_id,
        mcp_server_id=server_id, tool_name=tool_name,
        tool_input=tool_input, tool_output=response_body,
        outcome=outcome, duration_ms=duration_ms,
        severity=severity,
        error_message=response_body.get("error") if isinstance(response_body, dict) else None,
        trace_id=trace_id, session_id=x_session_id,
        caller_ip=caller_ip,
        token_scopes=token_ctx.scopes,
        policy_decision=decision.reason,
    ))

    # ── 6. Return response with rate-limit headers ────────────────────────────
    headers = {
        "x-trace-id": trace_id,
        "x-mcp-server-id": server_id,
        "x-mcp-tool-name": tool_name,
    }
    if decision.remaining_rpm is not None:
        headers["x-ratelimit-remaining-rpm"] = str(decision.remaining_rpm)
    if decision.remaining_rpd is not None:
        headers["x-ratelimit-remaining-rpd"] = str(decision.remaining_rpd)

    return JSONResponse(status_code=status_code, content=response_body, headers=headers)


def _elapsed(start_ms: float) -> float:
    return round((time.monotonic() * 1000) - start_ms, 2)
