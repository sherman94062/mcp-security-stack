import json
import uuid
import secrets
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy import select, update

from .models import Base, OAuthClient, AuthorizationCode, AccessToken, RefreshToken
from .config import settings


engine = create_async_engine(settings.DATABASE_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session


# ── Client operations ─────────────────────────────────────────────────────────

async def create_client(
    db: AsyncSession,
    client_name: str,
    redirect_uris: list,
    scopes: list,
    is_public: bool,
    client_secret_hash: Optional[str] = None,
) -> OAuthClient:
    client = OAuthClient(
        client_id=str(uuid.uuid4()),
        client_name=client_name,
        redirect_uris=json.dumps(redirect_uris),
        scopes=json.dumps(scopes),
        is_public=is_public,
        client_secret_hash=client_secret_hash,
    )
    db.add(client)
    await db.commit()
    await db.refresh(client)
    return client


async def get_client(db: AsyncSession, client_id: str) -> Optional[OAuthClient]:
    result = await db.execute(select(OAuthClient).where(OAuthClient.client_id == client_id))
    return result.scalar_one_or_none()


# ── Authorization code operations ─────────────────────────────────────────────

async def create_auth_code(
    db: AsyncSession,
    client_id: str,
    user_id: str,
    redirect_uri: str,
    scopes: list,
    code_challenge: Optional[str],
    code_challenge_method: Optional[str],
) -> AuthorizationCode:
    code = AuthorizationCode(
        code=secrets.token_urlsafe(32),
        client_id=client_id,
        user_id=user_id,
        redirect_uri=redirect_uri,
        scopes=json.dumps(scopes),
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        expires_at=datetime.utcnow() + timedelta(minutes=settings.AUTH_CODE_EXPIRE_MINUTES),
    )
    db.add(code)
    await db.commit()
    await db.refresh(code)
    return code


async def get_auth_code(db: AsyncSession, code: str) -> Optional[AuthorizationCode]:
    result = await db.execute(
        select(AuthorizationCode).where(AuthorizationCode.code == code)
    )
    return result.scalar_one_or_none()


async def consume_auth_code(db: AsyncSession, code: str):
    await db.execute(
        update(AuthorizationCode).where(AuthorizationCode.code == code).values(used=True)
    )
    await db.commit()


# ── Access token operations ───────────────────────────────────────────────────

async def create_access_token(
    db: AsyncSession,
    client_id: str,
    user_id: str,
    scopes: list,
    mcp_server_id: Optional[str] = None,
    tool_allowlist: Optional[list] = None,
) -> AccessToken:
    token = AccessToken(
        token=secrets.token_urlsafe(48),
        client_id=client_id,
        user_id=user_id,
        scopes=json.dumps(scopes),
        expires_at=datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        mcp_server_id=mcp_server_id,
        tool_allowlist=json.dumps(tool_allowlist) if tool_allowlist else None,
    )
    db.add(token)
    await db.commit()
    await db.refresh(token)
    return token


async def get_access_token(db: AsyncSession, token: str) -> Optional[AccessToken]:
    result = await db.execute(select(AccessToken).where(AccessToken.token == token))
    return result.scalar_one_or_none()


async def revoke_access_token(db: AsyncSession, token: str):
    await db.execute(
        update(AccessToken).where(AccessToken.token == token).values(revoked=True)
    )
    await db.commit()


# ── Refresh token operations ──────────────────────────────────────────────────

async def create_refresh_token(
    db: AsyncSession,
    access_token: str,
    client_id: str,
    user_id: str,
    scopes: list,
) -> RefreshToken:
    rt = RefreshToken(
        token=secrets.token_urlsafe(48),
        access_token=access_token,
        client_id=client_id,
        user_id=user_id,
        scopes=json.dumps(scopes),
        expires_at=datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )
    db.add(rt)
    await db.commit()
    await db.refresh(rt)
    return rt


async def get_refresh_token(db: AsyncSession, token: str) -> Optional[RefreshToken]:
    result = await db.execute(select(RefreshToken).where(RefreshToken.token == token))
    return result.scalar_one_or_none()


async def revoke_refresh_token(db: AsyncSession, token: str):
    await db.execute(
        update(RefreshToken).where(RefreshToken.token == token).values(revoked=True)
    )
    await db.commit()
