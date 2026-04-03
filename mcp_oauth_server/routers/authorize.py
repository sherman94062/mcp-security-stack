import json
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
from urllib.parse import urlencode

from ..storage import get_db, get_client, create_auth_code
from ..oauth import validate_redirect_uri, validate_requested_scopes, parse_scopes
from ..config import settings

router = APIRouter(prefix="/authorize", tags=["Authorization"])


@router.get("")
async def authorize(
    response_type: str = Query(...),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query(default=""),
    state: Optional[str] = Query(default=None),
    code_challenge: Optional[str] = Query(default=None),
    code_challenge_method: Optional[str] = Query(default="S256"),
    # In a real deployment, user_id comes from your session/auth middleware.
    # For this server we accept it as a header or query param for demo purposes.
    user_id: str = Query(default="demo_user"),
    db: AsyncSession = Depends(get_db),
):
    """
    OAuth 2.0 Authorization Endpoint (RFC 6749 §3.1).
    Supports PKCE (RFC 7636) — required when REQUIRE_PKCE=true.

    In production, this endpoint renders a login/consent UI.
    Here it auto-approves for testing purposes.
    """

    # ── Validate response_type ────────────────────────────────────────────────
    if response_type != "code":
        raise HTTPException(status_code=400, detail="Only response_type=code is supported")

    # ── Load and validate client ──────────────────────────────────────────────
    client = await get_client(db, client_id)
    if not client or not client.is_active:
        raise HTTPException(status_code=400, detail="Unknown or inactive client_id")

    registered_uris = json.loads(client.redirect_uris)
    if not validate_redirect_uri(redirect_uri, registered_uris):
        raise HTTPException(status_code=400, detail="redirect_uri not registered for this client")

    # ── PKCE enforcement ──────────────────────────────────────────────────────
    if settings.REQUIRE_PKCE or client.is_public:
        if not code_challenge:
            return _error_redirect(redirect_uri, "invalid_request",
                                   "code_challenge required", state)
        if code_challenge_method not in ("S256", "plain"):
            return _error_redirect(redirect_uri, "invalid_request",
                                   "code_challenge_method must be S256 or plain", state)
        # Strongly recommend S256
        if code_challenge_method == "plain":
            # Allow but log — in production you may want to reject plain
            pass

    # ── Scope validation ──────────────────────────────────────────────────────
    requested_scopes = parse_scopes(scope)
    client_scopes = json.loads(client.scopes)
    approved_scopes = validate_requested_scopes(requested_scopes, client_scopes)

    # ── Issue authorization code ──────────────────────────────────────────────
    auth_code = await create_auth_code(
        db=db,
        client_id=client_id,
        user_id=user_id,
        redirect_uri=redirect_uri,
        scopes=approved_scopes,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
    )

    # ── Redirect back to client ───────────────────────────────────────────────
    params = {"code": auth_code.code}
    if state:
        params["state"] = state

    return RedirectResponse(f"{redirect_uri}?{urlencode(params)}")


def _error_redirect(redirect_uri: str, error: str, description: str, state: Optional[str]):
    params = {"error": error, "error_description": description}
    if state:
        params["state"] = state
    return RedirectResponse(f"{redirect_uri}?{urlencode(params)}")
