import base64
import hashlib
import json
import secrets
from datetime import datetime
from typing import Optional

from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_secret(secret: str) -> str:
    return pwd_context.hash(secret)


def verify_secret(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def generate_client_secret() -> str:
    return secrets.token_urlsafe(32)


# ── PKCE ──────────────────────────────────────────────────────────────────────

def verify_code_verifier(verifier: str, challenge: str, method: str) -> bool:
    """Verify PKCE code_verifier against stored code_challenge."""
    if method == "S256":
        digest = hashlib.sha256(verifier.encode()).digest()
        computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        return computed == challenge
    elif method == "plain":
        return verifier == challenge
    return False


# ── Scope utilities ───────────────────────────────────────────────────────────

# MCP-specific scopes.
# Format: mcp:{server_id}:{tool_name} or mcp:{server_id}:*
MCP_SCOPE_PREFIX = "mcp:"

STANDARD_SCOPES = {
    "openid": "OpenID Connect identity",
    "profile": "Basic profile information",
    "offline_access": "Refresh token access",
}


def parse_scopes(scope_string: str) -> list:
    return [s.strip() for s in scope_string.split() if s.strip()]


def scopes_to_string(scopes: list) -> str:
    return " ".join(scopes)


def validate_requested_scopes(requested: list, client_allowed: list) -> list:
    """Return only scopes that the client is registered for."""
    if not client_allowed:
        return requested  # No restriction registered
    return [s for s in requested if s in client_allowed]


def extract_mcp_tool_allowlist(scopes: list) -> Optional[list]:
    """Extract tool names from MCP scopes like mcp:payments:transfer_funds."""
    tools = []
    for scope in scopes:
        if scope.startswith(MCP_SCOPE_PREFIX):
            parts = scope.split(":")
            if len(parts) == 3:
                tools.append(parts[2])  # tool name
    return tools if tools else None


# ── Token validation helpers ──────────────────────────────────────────────────

def is_token_expired(expires_at: datetime) -> bool:
    return datetime.utcnow() > expires_at


def validate_redirect_uri(requested_uri: str, registered_uris: list) -> bool:
    """Exact match required per OAuth 2.0 spec."""
    return requested_uri in registered_uris
