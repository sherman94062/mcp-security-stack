from fastapi import APIRouter, Depends, Form, HTTPException
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from ..storage import get_db, get_access_token, get_refresh_token, revoke_access_token, revoke_refresh_token, get_client
from ..oauth import verify_secret

router = APIRouter(prefix="/revoke", tags=["Revocation"])


@router.post("", status_code=200)
async def revoke(
    token: str = Form(...),
    token_type_hint: str = Form(default="access_token"),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    """
    RFC 7009 Token Revocation.
    Agents or servers call this on logout, credential rotation, or suspected compromise.
    Always returns 200 per spec — never reveals whether token existed.
    """

    # Authenticate caller
    client = await get_client(db, client_id)
    if not client or not client.is_active:
        raise HTTPException(status_code=401, detail="invalid_client")
    if not client.is_public:
        if not verify_secret(client_secret, client.client_secret_hash):
            raise HTTPException(status_code=401, detail="invalid_client")

    # Try access token first, then refresh token
    if token_type_hint == "refresh_token":
        rt = await get_refresh_token(db, token)
        if rt and rt.client_id == client_id:
            await revoke_refresh_token(db, token)
            # Also revoke the associated access token
            await revoke_access_token(db, rt.access_token)
    else:
        at = await get_access_token(db, token)
        if at and at.client_id == client_id:
            await revoke_access_token(db, token)

    # Per RFC 7009: always return 200, even if token wasn't found
    return Response(status_code=200)
