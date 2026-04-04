"""
Proxies validated, policy-approved requests to backend MCP servers.
Forwards the original request body and headers, streams the response back.
"""

import time
import logging
from typing import Optional

import httpx

from .config import gateway_settings

logger = logging.getLogger("mcp_gateway.proxy")


async def forward_request(
    base_url:   str,
    tool_name:  str,
    tool_input: dict,
    headers:    dict,
    trace_id:   Optional[str] = None,
) -> tuple[int, dict, float]:
    """
    Forward a tool call to the backend MCP server.

    Convention: POST {base_url}/tools/{tool_name}
    Returns: (status_code, response_body_dict, duration_ms)
    """
    url = f"{base_url.rstrip('/')}/tools/{tool_name}"

    forward_headers = {
        "Content-Type": "application/json",
    }
    # Propagate tracing headers
    if trace_id:
        forward_headers["x-trace-id"] = trace_id
    # Forward auth if backend requires it (strip the original bearer, use server-to-server creds)
    if "x-mcp-backend-key" in headers:
        forward_headers["Authorization"] = f"Bearer {headers['x-mcp-backend-key']}"

    start = time.monotonic() * 1000

    try:
        async with httpx.AsyncClient(timeout=gateway_settings.BACKEND_TIMEOUT_SECONDS) as client:
            resp = await client.post(url, json=tool_input, headers=forward_headers)
            duration_ms = (time.monotonic() * 1000) - start

            try:
                body = resp.json()
            except Exception:
                body = {"_raw": resp.text}

            return resp.status_code, body, duration_ms

    except httpx.TimeoutException:
        duration_ms = (time.monotonic() * 1000) - start
        logger.error("Timeout calling backend %s tool %s after %.0fms", base_url, tool_name, duration_ms)
        return 504, {"error": "backend_timeout", "tool": tool_name}, duration_ms

    except Exception as exc:
        duration_ms = (time.monotonic() * 1000) - start
        logger.error("Backend call failed %s tool %s: %s", base_url, tool_name, exc)
        return 502, {"error": "backend_unavailable", "detail": str(exc)}, duration_ms


async def check_backend_health(health_url: str) -> bool:
    """Lightweight health probe for a backend MCP server."""
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(health_url)
            return resp.status_code == 200
    except Exception:
        return False
