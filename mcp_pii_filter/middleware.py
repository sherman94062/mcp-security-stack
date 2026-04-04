"""
Drop-in ASGI middleware that auto-filters PII from MCP tool I/O.

Usage in your MCP server:

    from mcp_pii_filter.middleware import PIIFilterMiddleware

    app = FastAPI()
    app.add_middleware(
        PIIFilterMiddleware,
        filter_server_url="http://localhost:8084",
        filter_api_key="your-filter-key",
        server_id="payments-server",
        filter_inputs=True,
        filter_outputs=True,
    )

All requests to /tools/* have their request body and response body
automatically scanned and redacted before logging or forwarding.
If a rule has action=BLOCK and PII is found in input, the request
is rejected with 422 before it reaches the tool handler.
"""

import json
import logging
from typing import Callable, Optional

import httpx
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logger = logging.getLogger("mcp_pii.middleware")


class PIIFilterMiddleware(BaseHTTPMiddleware):

    def __init__(
        self,
        app,
        filter_server_url: str,
        filter_api_key: str,
        server_id: str,
        tool_path_prefix: str = "/tools",
        filter_inputs: bool = True,
        filter_outputs: bool = True,
        client_id_header: str = "x-mcp-client-id",
    ):
        super().__init__(app)
        self.filter_url      = filter_server_url.rstrip("/") + "/filter"
        self.filter_api_key  = filter_api_key
        self.server_id       = server_id
        self.tool_prefix     = tool_path_prefix
        self.filter_inputs   = filter_inputs
        self.filter_outputs  = filter_outputs
        self.client_id_header = client_id_header

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if not request.url.path.startswith(self.tool_prefix):
            return await call_next(request)

        tool_name = request.url.path.removeprefix(self.tool_prefix).strip("/") or "unknown"
        client_id = request.headers.get(self.client_id_header, "unknown")
        trace_id  = request.headers.get("x-trace-id")

        # ── Filter input ──────────────────────────────────────────────────────
        if self.filter_inputs:
            body_bytes = await request.body()
            try:
                payload = json.loads(body_bytes) if body_bytes else {}
            except Exception:
                payload = {}

            filtered, blocked = await self._call_filter(
                payload, tool_name, client_id, "input", trace_id
            )

            if blocked:
                return JSONResponse(
                    status_code=422,
                    content={
                        "error": "pii_blocked",
                        "detail": "Request payload contains PII that is not permitted for this tool",
                    },
                )

            # Rebuild request with clean payload
            clean_body = json.dumps(filtered).encode()
            request._body = clean_body  # Patch for downstream handlers

        # ── Call the actual tool handler ──────────────────────────────────────
        response = await call_next(request)

        # ── Filter output ─────────────────────────────────────────────────────
        if self.filter_outputs:
            resp_body = b""
            async for chunk in response.body_iterator:
                resp_body += chunk

            try:
                resp_payload = json.loads(resp_body) if resp_body else {}
            except Exception:
                resp_payload = {}

            filtered_output, _ = await self._call_filter(
                resp_payload, tool_name, client_id, "output", trace_id
            )

            return Response(
                content=json.dumps(filtered_output),
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type="application/json",
            )

        return response

    async def _call_filter(
        self,
        payload: dict,
        tool_name: str,
        client_id: str,
        direction: str,
        trace_id: Optional[str],
    ) -> tuple[dict, bool]:
        """POST to PII filter server. Returns (clean_payload, blocked)."""
        request_body = {
            "payload":   payload,
            "server_id": self.server_id,
            "tool_name": tool_name,
            "client_id": client_id,
            "direction": direction,
            "trace_id":  trace_id,
        }
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.post(
                    self.filter_url,
                    json=request_body,
                    headers={"x-pii-filter-key": self.filter_api_key},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return data["clean_payload"], data.get("blocked", False)
        except Exception as exc:
            # Filter server unavailable — fail open (log and pass through)
            # Change to fail closed by returning ({}, True) if your policy requires it
            logger.error("PII filter server unreachable for %s/%s: %s", self.server_id, tool_name, exc)

        return payload, False  # Fail open
