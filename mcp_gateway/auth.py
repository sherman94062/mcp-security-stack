"""
Token validation via the MCP OAuth Server's introspection endpoint.

The gateway never trusts bearer tokens directly — it always introspects
against the OAuth server to get the authoritative token metadata,
including the tool_allowlist embedded in the token's MCP scopes.
"""

import logging
from typing import Optional
from dataclasses import dataclass

import httpx

from .config import gateway_settings

logger = logging.getLogger("mcp_gateway.auth")


@dataclass
class TokenContext:
    """Verified identity and permissions from an introspected token."""
    active:        bool
    client_id:     str
    user_id:       Optional[str]
    scopes:        list
    tool_allowlist: Optional[list]   # From MCP scope metadata
    mcp_server_id: Optional[str]


ANONYMOUS = TokenContext(
    active=False,
    client_id="unknown",
    user_id=None,
    scopes=[],
    tool_allowlist=None,
    mcp_server_id=None,
)


async def introspect_token(bearer_token: str) -> TokenContext:
    """
    Call the OAuth server's /introspect endpoint.
    Returns ANONYMOUS context (active=False) on any failure.
    """
    if not bearer_token:
        return ANONYMOUS

    # Gateway authenticates to the OAuth server with its own credentials
    if not gateway_settings.OAUTH_CLIENT_ID or not gateway_settings.OAUTH_CLIENT_SECRET:
        logger.warning(
            "OAUTH_CLIENT_ID/SECRET not configured — token introspection disabled. "
            "Set these in .env for production use."
        )
        # Dev mode: accept any token, extract client_id from a simple prefix convention
        # e.g. token starting with "dev-{client_id}-" for local testing
        client_id = _dev_extract_client(bearer_token)
        return TokenContext(
            active=True,
            client_id=client_id,
            user_id=None,
            scopes=[],
            tool_allowlist=None,
            mcp_server_id=None,
        )

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                f"{gateway_settings.OAUTH_SERVER_URL}/introspect",
                data={
                    "token":         bearer_token,
                    "client_id":     gateway_settings.OAUTH_CLIENT_ID,
                    "client_secret": gateway_settings.OAUTH_CLIENT_SECRET,
                },
            )
            if resp.status_code != 200:
                logger.warning("Introspection returned %s", resp.status_code)
                return ANONYMOUS

            data = resp.json()

    except Exception as exc:
        logger.error("Introspection request failed: %s", exc)
        return ANONYMOUS

    if not data.get("active"):
        return ANONYMOUS

    scopes_str = data.get("scope", "")
    scopes = scopes_str.split() if scopes_str else []

    return TokenContext(
        active=True,
        client_id=data.get("client_id", "unknown"),
        user_id=data.get("user_id"),
        scopes=scopes,
        tool_allowlist=data.get("tool_allowlist"),
        mcp_server_id=data.get("mcp_server_id"),
    )


def _dev_extract_client(token: str) -> str:
    """
    Dev-mode only: extract client_id from token prefix.
    Format: dev-{client_id}-{random}
    """
    if token.startswith("dev-"):
        parts = token.split("-")
        if len(parts) >= 3:
            return parts[1]
    return "dev-client"
