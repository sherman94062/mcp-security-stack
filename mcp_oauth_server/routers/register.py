import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import ClientRegistrationRequest, ClientRegistrationResponse
from ..storage import get_db, create_client
from ..oauth import hash_secret, generate_client_secret

router = APIRouter(prefix="/register", tags=["Client Registration"])


@router.post("", response_model=ClientRegistrationResponse, status_code=201)
async def register_client(
    request: ClientRegistrationRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    RFC 7591 Dynamic Client Registration.
    MCP servers/agents register here to obtain a client_id.
    Public clients (is_public=True) use PKCE only — no client secret issued.
    """
    if not request.redirect_uris:
        raise HTTPException(status_code=400, detail="At least one redirect_uri is required")

    client_secret = None
    secret_hash = None

    if not request.is_public:
        client_secret = generate_client_secret()
        secret_hash = hash_secret(client_secret)

    client = await create_client(
        db=db,
        client_name=request.client_name,
        redirect_uris=request.redirect_uris,
        scopes=request.scopes,
        is_public=request.is_public,
        client_secret_hash=secret_hash,
    )

    return ClientRegistrationResponse(
        client_id=client.client_id,
        client_secret=client_secret,  # Only returned once at registration
        client_name=client.client_name,
        redirect_uris=json.loads(client.redirect_uris),
        scopes=json.loads(client.scopes),
        is_public=client.is_public,
    )
