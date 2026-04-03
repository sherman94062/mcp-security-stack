import json
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Form, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from ..storage import get_db, get_access_token, get_client
from ..models import TokenIntrospectionResponse
from ..oauth import is_token_expired, verify_secret

router = APIRouter(prefix="/introspect", tags=["Introspection"])


@router.post("", response_model=TokenIntrospectionResponse)
async def introspect(
    token: str = Form(...),
    # MCP servers call this endpoint — they authenticate with their own credentials
    client_id: str = Form(...),
    client_secret: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    """
    RFC 7662 Token Introspection.
    MCP servers call this to validate incoming bearer tokens before executing tools.
    Returns active=False for any invalid/expired/revoked token (never an error).
    Also returns MCP-specific metadata: mcp_server_id and tool_allowlist.
    """

    # Authenticate the calling MCP server
    caller = await get_client(db, client_id)
    if not caller or not caller.is_active or caller.is_public:
        raise HTTPException(status_code=401, detail="invalid_client")
    if not verify_secret(client_secret, caller.client_secret_hash):
        raise HTTPException(status_code=401, detail="invalid_client")

    # Look up the token
    access_token = await get_access_token(db, token)

    if not access_token or access_token.revoked or is_token_expired(access_token.expires_at):
        return TokenIntrospectionResponse(active=False)

    scopes = json.loads(access_token.scopes)
    tool_allowlist = json.loads(access_token.tool_allowlist) if access_token.tool_allowlist else None

    return TokenIntrospectionResponse(
        active=True,
        client_id=access_token.client_id,
        user_id=access_token.user_id,
        scope=" ".join(scopes),
        exp=int(access_token.expires_at.timestamp()),
        iat=int(access_token.created_at.timestamp()),
        mcp_server_id=access_token.mcp_server_id,
        tool_allowlist=tool_allowlist,
    )
