import json
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Form
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional

from ..storage import (
    get_db, get_client, get_auth_code, consume_auth_code,
    create_access_token, create_refresh_token,
    get_refresh_token, revoke_refresh_token, revoke_access_token,
)
from ..models import TokenResponse
from ..oauth import (
    verify_secret, verify_code_verifier, is_token_expired,
    extract_mcp_tool_allowlist,
)
from ..config import settings

router = APIRouter(prefix="/token", tags=["Token"])


@router.post("", response_model=TokenResponse)
async def token(
    grant_type: str = Form(...),
    # Authorization code grant
    code: Optional[str] = Form(default=None),
    redirect_uri: Optional[str] = Form(default=None),
    code_verifier: Optional[str] = Form(default=None),
    # Refresh token grant
    refresh_token: Optional[str] = Form(default=None),
    # Client credentials (for M2M agent-to-agent)
    scope: Optional[str] = Form(default=None),
    # Client auth
    client_id: Optional[str] = Form(default=None),
    client_secret: Optional[str] = Form(default=None),
    db: AsyncSession = Depends(get_db),
):
    """
    OAuth 2.0 Token Endpoint (RFC 6749 §3.2).
    Supports:
      - authorization_code  (human user flows with PKCE)
      - refresh_token       (token renewal)
      - client_credentials  (M2M agent-to-agent flows)
    """

    if grant_type == "authorization_code":
        return await _authorization_code_grant(
            db, code, redirect_uri, code_verifier, client_id, client_secret
        )
    elif grant_type == "refresh_token":
        return await _refresh_token_grant(db, refresh_token, client_id, client_secret)
    elif grant_type == "client_credentials":
        return await _client_credentials_grant(db, client_id, client_secret, scope)
    else:
        raise HTTPException(status_code=400, detail="unsupported_grant_type")


# ── Authorization Code Grant ──────────────────────────────────────────────────

async def _authorization_code_grant(
    db, code, redirect_uri, code_verifier, client_id, client_secret
):
    if not code:
        raise HTTPException(status_code=400, detail="code is required")

    auth_code = await get_auth_code(db, code)

    if not auth_code:
        raise HTTPException(status_code=400, detail="invalid_grant: code not found")
    if auth_code.used:
        raise HTTPException(status_code=400, detail="invalid_grant: code already used")
    if is_token_expired(auth_code.expires_at):
        raise HTTPException(status_code=400, detail="invalid_grant: code expired")

    # Validate client
    if auth_code.client_id != client_id:
        raise HTTPException(status_code=400, detail="invalid_client")

    client = await get_client(db, client_id)
    if not client or not client.is_active:
        raise HTTPException(status_code=400, detail="invalid_client")

    # Client secret check for confidential clients
    if not client.is_public:
        if not client_secret or not verify_secret(client_secret, client.client_secret_hash):
            raise HTTPException(status_code=401, detail="invalid_client: bad credentials")

    # PKCE verification
    if auth_code.code_challenge:
        if not code_verifier:
            raise HTTPException(status_code=400, detail="invalid_grant: code_verifier required")
        if not verify_code_verifier(code_verifier, auth_code.code_challenge,
                                    auth_code.code_challenge_method or "S256"):
            raise HTTPException(status_code=400, detail="invalid_grant: code_verifier mismatch")

    # Redirect URI must match
    if redirect_uri and redirect_uri != auth_code.redirect_uri:
        raise HTTPException(status_code=400, detail="invalid_grant: redirect_uri mismatch")

    # Consume the code (one-time use)
    await consume_auth_code(db, code)

    scopes = json.loads(auth_code.scopes)
    tool_allowlist = extract_mcp_tool_allowlist(scopes)

    access_token = await create_access_token(
        db=db,
        client_id=client_id,
        user_id=auth_code.user_id,
        scopes=scopes,
        tool_allowlist=tool_allowlist,
    )

    refresh_token = await create_refresh_token(
        db=db,
        access_token=access_token.token,
        client_id=client_id,
        user_id=auth_code.user_id,
        scopes=scopes,
    )

    return TokenResponse(
        access_token=access_token.token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        refresh_token=refresh_token.token,
        scope=" ".join(scopes),
    )


# ── Refresh Token Grant ───────────────────────────────────────────────────────

async def _refresh_token_grant(db, refresh_token_str, client_id, client_secret):
    if not refresh_token_str:
        raise HTTPException(status_code=400, detail="refresh_token is required")

    rt = await get_refresh_token(db, refresh_token_str)
    if not rt or rt.revoked:
        raise HTTPException(status_code=400, detail="invalid_grant: refresh token invalid")
    if is_token_expired(rt.expires_at):
        raise HTTPException(status_code=400, detail="invalid_grant: refresh token expired")
    if rt.client_id != client_id:
        raise HTTPException(status_code=400, detail="invalid_client")

    client = await get_client(db, client_id)
    if not client or not client.is_active:
        raise HTTPException(status_code=400, detail="invalid_client")

    if not client.is_public:
        if not client_secret or not verify_secret(client_secret, client.client_secret_hash):
            raise HTTPException(status_code=401, detail="invalid_client: bad credentials")

    # Rotate: revoke old tokens, issue new ones
    await revoke_refresh_token(db, refresh_token_str)
    await revoke_access_token(db, rt.access_token)

    scopes = json.loads(rt.scopes)
    tool_allowlist = extract_mcp_tool_allowlist(scopes)

    new_access_token = await create_access_token(
        db=db,
        client_id=client_id,
        user_id=rt.user_id,
        scopes=scopes,
        tool_allowlist=tool_allowlist,
    )
    new_refresh_token = await create_refresh_token(
        db=db,
        access_token=new_access_token.token,
        client_id=client_id,
        user_id=rt.user_id,
        scopes=scopes,
    )

    return TokenResponse(
        access_token=new_access_token.token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        refresh_token=new_refresh_token.token,
        scope=" ".join(scopes),
    )


# ── Client Credentials Grant (M2M / agent-to-agent) ──────────────────────────

async def _client_credentials_grant(db, client_id, client_secret, scope):
    if not client_id or not client_secret:
        raise HTTPException(status_code=401, detail="invalid_client: credentials required")

    client = await get_client(db, client_id)
    if not client or not client.is_active or client.is_public:
        raise HTTPException(status_code=401, detail="invalid_client")

    if not verify_secret(client_secret, client.client_secret_hash):
        raise HTTPException(status_code=401, detail="invalid_client: bad credentials")

    requested_scopes = scope.split() if scope else []
    client_scopes = json.loads(client.scopes)
    approved_scopes = [s for s in requested_scopes if s in client_scopes] if client_scopes else requested_scopes

    tool_allowlist = extract_mcp_tool_allowlist(approved_scopes)

    access_token = await create_access_token(
        db=db,
        client_id=client_id,
        user_id=client_id,  # No user in M2M; use client_id as subject
        scopes=approved_scopes,
        tool_allowlist=tool_allowlist,
    )

    return TokenResponse(
        access_token=access_token.token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        scope=" ".join(approved_scopes),
    )
