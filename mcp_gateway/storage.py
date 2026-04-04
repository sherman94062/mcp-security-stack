import json
from datetime import datetime
from typing import Optional, List

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from .models import Base, MCPServer, Policy, RateLimitCounter, PolicyCreate
from .config import gateway_settings

engine = create_async_engine(gateway_settings.DATABASE_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


async def init_gateway_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session


# ── Server registry ───────────────────────────────────────────────────────────

async def register_server(db: AsyncSession, data) -> MCPServer:
    existing = await get_server(db, data.server_id)
    if existing:
        # Upsert
        await db.execute(
            update(MCPServer)
            .where(MCPServer.server_id == data.server_id)
            .values(
                display_name=data.display_name,
                base_url=data.base_url,
                description=data.description,
                health_url=data.health_url,
                is_active=True,
            )
        )
        await db.commit()
        return await get_server(db, data.server_id)

    server = MCPServer(
        server_id=data.server_id,
        display_name=data.display_name,
        base_url=data.base_url,
        description=data.description,
        health_url=data.health_url,
    )
    db.add(server)
    await db.commit()
    await db.refresh(server)
    return server


async def get_server(db: AsyncSession, server_id: str) -> Optional[MCPServer]:
    result = await db.execute(select(MCPServer).where(MCPServer.server_id == server_id))
    return result.scalar_one_or_none()


async def list_servers(db: AsyncSession) -> List[MCPServer]:
    result = await db.execute(select(MCPServer).where(MCPServer.is_active == True))
    return result.scalars().all()


# ── Policy management ─────────────────────────────────────────────────────────

async def create_policy(db: AsyncSession, data: PolicyCreate) -> Policy:
    policy = Policy(
        client_id=data.client_id,
        server_id=data.server_id,
        allowed_tools=json.dumps(data.allowed_tools),
        effect=data.effect.value,
        rate_limit_rpm=data.rate_limit_rpm,
        rate_limit_rpd=data.rate_limit_rpd,
        notes=data.notes,
    )
    db.add(policy)
    await db.commit()
    await db.refresh(policy)
    return policy


async def get_policies_for_client(
    db: AsyncSession, client_id: str, server_id: str
) -> List[Policy]:
    """
    Return policies matching this client+server, plus any wildcard policies.
    More-specific policies (exact client match) take precedence.
    """
    result = await db.execute(
        select(Policy).where(
            Policy.is_active == True,
            Policy.server_id.in_([server_id, "*"]),
            Policy.client_id.in_([client_id, "*"]),
        )
    )
    policies = result.scalars().all()
    # Sort: exact client match first, then wildcards
    return sorted(policies, key=lambda p: (p.client_id == "*", p.server_id == "*"))


async def list_policies(db: AsyncSession, client_id: Optional[str] = None) -> List[Policy]:
    stmt = select(Policy).where(Policy.is_active == True)
    if client_id:
        stmt = stmt.where(Policy.client_id == client_id)
    result = await db.execute(stmt)
    return result.scalars().all()


async def deactivate_policy(db: AsyncSession, policy_id: str):
    await db.execute(
        update(Policy).where(Policy.policy_id == policy_id).values(is_active=False)
    )
    await db.commit()


# ── Rate limit counters ───────────────────────────────────────────────────────

def _window_key(window: str) -> str:
    now = datetime.utcnow()
    if window == "minute":
        return now.strftime("%Y-%m-%dT%H:%M")
    elif window == "hour":
        return now.strftime("%Y-%m-%dT%H")
    else:  # day
        return now.strftime("%Y-%m-%d")


async def increment_and_get_count(
    db: AsyncSession, client_id: str, server_id: str, window: str
) -> int:
    key = _window_key(window)
    result = await db.execute(
        select(RateLimitCounter).where(
            RateLimitCounter.client_id == client_id,
            RateLimitCounter.server_id == server_id,
            RateLimitCounter.window == window,
            RateLimitCounter.window_key == key,
        )
    )
    counter = result.scalar_one_or_none()

    if counter:
        counter.count += 1
        counter.updated_at = datetime.utcnow()
        await db.commit()
        return counter.count
    else:
        counter = RateLimitCounter(
            client_id=client_id,
            server_id=server_id,
            window=window,
            window_key=key,
            count=1,
        )
        db.add(counter)
        await db.commit()
        return 1


async def get_current_count(
    db: AsyncSession, client_id: str, server_id: str, window: str
) -> int:
    key = _window_key(window)
    result = await db.execute(
        select(RateLimitCounter).where(
            RateLimitCounter.client_id == client_id,
            RateLimitCounter.server_id == server_id,
            RateLimitCounter.window == window,
            RateLimitCounter.window_key == key,
        )
    )
    counter = result.scalar_one_or_none()
    return counter.count if counter else 0
