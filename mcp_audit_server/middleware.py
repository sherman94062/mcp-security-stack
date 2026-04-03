"""
Drop-in audit middleware for FastAPI-based MCP servers.

Usage in your MCP server:

    from mcp_audit_server.middleware import MCPAuditMiddleware

    app = FastAPI()
    app.add_middleware(
        MCPAuditMiddleware,
        audit_server_url="http://localhost:8081",
        audit_api_key="your-ingest-key",
        mcp_server_id="payments-server",
    )

Every request to /tools/* is automatically logged to the audit server.
"""

import json
import time
import logging
from typing import Optional, Callable

import httpx
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger("mcp_audit.middleware")


class MCPAuditMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        audit_server_url: str,
        audit_api_key: str,
        mcp_server_id: str,
        tool_path_prefix: str = "/tools",
        redact_inputs: bool = False,
        redact_outputs: bool = False,
    ):
        super().__init__(app)
        self.audit_server_url = audit_server_url.rstrip("/")
        self.audit_api_key    = audit_api_key
        self.mcp_server_id    = mcp_server_id
        self.tool_path_prefix = tool_path_prefix
        self.redact_inputs    = redact_inputs
        self.redact_outputs   = redact_outputs

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Only audit tool-invocation paths
        if not request.url.path.startswith(self.tool_path_prefix):
            return await call_next(request)

        start_ms = time.monotonic() * 1000

        # Capture request body
        body_bytes = await request.body()
        try:
            tool_input = json.loads(body_bytes) if body_bytes else None
        except Exception:
            tool_input = {"_raw": body_bytes.decode(errors="replace")}

        # Extract context from headers
        client_id  = request.headers.get("x-mcp-client-id", "unknown")
        user_id    = request.headers.get("x-mcp-user-id")
        agent_name = request.headers.get("x-mcp-agent-name")
        trace_id   = request.headers.get("x-trace-id") or request.headers.get("x-request-id")
        session_id = request.headers.get("x-mcp-session-id")
        caller_ip  = request.client.host if request.client else None

        # Derive tool name from path: /tools/transfer_funds → transfer_funds
        tool_name = request.url.path.removeprefix(self.tool_path_prefix).strip("/") or "unknown"

        # Execute the actual handler
        response = await call_next(request)
        duration_ms = (time.monotonic() * 1000) - start_ms

        # Capture response body
        resp_body = b""
        async for chunk in response.body_iterator:
            resp_body += chunk
        try:
            tool_output = json.loads(resp_body) if resp_body else None
        except Exception:
            tool_output = {"_raw": resp_body.decode(errors="replace")}

        # Determine outcome
        if response.status_code == 403:
            outcome = "denied"
        elif response.status_code >= 500:
            outcome = "error"
        elif response.status_code >= 400:
            outcome = "failure"
        else:
            outcome = "success"

        severity = "critical" if outcome in ("denied", "error") else "info"

        # Fire audit event (non-blocking)
        audit_payload = {
            "client_id":     client_id,
            "user_id":       user_id,
            "agent_name":    agent_name,
            "mcp_server_id": self.mcp_server_id,
            "tool_name":     tool_name,
            "tool_input":    None if self.redact_inputs else tool_input,
            "tool_output":   None if self.redact_outputs else tool_output,
            "outcome":       outcome,
            "duration_ms":   round(duration_ms, 2),
            "severity":      severity,
            "caller_ip":     caller_ip,
            "trace_id":      trace_id,
            "session_id":    session_id,
        }

        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                await client.post(
                    f"{self.audit_server_url}/events",
                    json=audit_payload,
                    headers={"x-audit-api-key": self.audit_api_key},
                )
        except Exception as exc:
            # Audit failure must NEVER block the actual tool response
            logger.error("Audit ingest failed for tool %s: %s", tool_name, exc)

        # Reconstruct response with captured body
        from starlette.responses import Response as StarletteResponse
        return StarletteResponse(
            content=resp_body,
            status_code=response.status_code,
            headers=dict(response.headers),
            media_type=response.media_type,
        )
