import fnmatch
import json
from datetime import datetime, timedelta
from typing import Optional, List

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from .models import Base, SecretDefinition, AccessPolicy, SecretLease, LeaseStatus
from .config import secrets_settings

engine = create_async_engine(secrets_settings.DATABASE_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


async def init_secrets_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session


# ── Secret definitions ────────────────────────────────────────────────────────

async def create_secret(db: AsyncSession, data) -> SecretDefinition:
    secret = SecretDefinition(
        name=data.name,
        description=data.description,
        backend=data.backend.value,
        backend_path=data.backend_path or data.name,
        encrypted_value=data.encrypted_value if hasattr(data, "encrypted_value") else None,
        tags=data.tags,
        created_by=data.created_by,
    )
    db.add(secret)
    await db.commit()
    await db.refresh(secret)
    return secret


async def get_secret_by_name(db: AsyncSession, name: str) -> Optional[SecretDefinition]:
    result = await db.execute(
        select(SecretDefinition).where(
            SecretDefinition.name == name,
            SecretDefinition.is_active == True,
        )
    )
    return result.scalar_one_or_none()


async def get_secret_by_id(db: AsyncSession, secret_id: str) -> Optional[SecretDefinition]:
    result = await db.execute(
        select(SecretDefinition).where(SecretDefinition.secret_id == secret_id)
    )
    return result.scalar_one_or_none()


async def list_secrets(db: AsyncSession) -> List[SecretDefinition]:
    result = await db.execute(
        select(SecretDefinition).where(SecretDefinition.is_active == True)
    )
    return result.scalars().all()


async def rotate_secret(
    db: AsyncSession, secret_id: str, new_encrypted_value: str
) -> SecretDefinition:
    await db.execute(
        update(SecretDefinition)
        .where(SecretDefinition.secret_id == secret_id)
        .values(encrypted_value=new_encrypted_value, rotated_at=datetime.utcnow())
    )
    await db.commit()
    return await get_secret_by_id(db, secret_id)


async def deactivate_secret(db: AsyncSession, secret_id: str):
    await db.execute(
        update(SecretDefinition)
        .where(SecretDefinition.secret_id == secret_id)
        .values(is_active=False)
    )
    await db.commit()


# ── Access policies ───────────────────────────────────────────────────────────

async def create_access_policy(db: AsyncSession, data) -> AccessPolicy:
    policy = AccessPolicy(
        client_id=data.client_id,
        secret_pattern=data.secret_pattern,
        max_lease_ttl=data.max_lease_ttl,
        notes=data.notes,
    )
    db.add(policy)
    await db.commit()
    await db.refresh(policy)
    return policy


async def get_access_policies(db: AsyncSession, client_id: str) -> List[AccessPolicy]:
    result = await db.execute(
        select(AccessPolicy).where(
            AccessPolicy.is_active == True,
            AccessPolicy.client_id.in_([client_id, "*"]),
        )
    )
    return result.scalars().all()


async def check_access(
    db: AsyncSession, client_id: str, secret_name: str
) -> tuple[bool, Optional[int]]:
    """
    Returns (is_allowed, max_lease_ttl).
    Uses fnmatch for wildcard patterns: "payments/*", "*".
    """
    policies = await get_access_policies(db, client_id)
    for policy in policies:
        if fnmatch.fnmatch(secret_name, policy.secret_pattern):
            return True, policy.max_lease_ttl
    return False, None


async def list_access_policies(
    db: AsyncSession, client_id: Optional[str] = None
) -> List[AccessPolicy]:
    stmt = select(AccessPolicy).where(AccessPolicy.is_active == True)
    if client_id:
        stmt = stmt.where(AccessPolicy.client_id == client_id)
    result = await db.execute(stmt)
    return result.scalars().all()


async def deactivate_access_policy(db: AsyncSession, policy_id: str):
    await db.execute(
        update(AccessPolicy)
        .where(AccessPolicy.policy_id == policy_id)
        .values(is_active=False)
    )
    await db.commit()


# ── Leases ────────────────────────────────────────────────────────────────────

async def create_lease(
    db: AsyncSession,
    secret: SecretDefinition,
    client_id: str,
    ttl_seconds: int,
    user_id: Optional[str] = None,
    trace_id: Optional[str] = None,
    caller_ip: Optional[str] = None,
    purpose: Optional[str] = None,
) -> SecretLease:
    lease = SecretLease(
        secret_id=secret.secret_id,
        secret_name=secret.name,
        client_id=client_id,
        user_id=user_id,
        status=LeaseStatus.ACTIVE.value,
        expires_at=datetime.utcnow() + timedelta(seconds=ttl_seconds),
        trace_id=trace_id,
        caller_ip=caller_ip,
        purpose=purpose,
    )
    db.add(lease)
    await db.commit()
    await db.refresh(lease)
    return lease


async def get_lease(db: AsyncSession, lease_id: str) -> Optional[SecretLease]:
    result = await db.execute(
        select(SecretLease).where(SecretLease.lease_id == lease_id)
    )
    return result.scalar_one_or_none()


async def revoke_lease(db: AsyncSession, lease_id: str):
    await db.execute(
        update(SecretLease)
        .where(SecretLease.lease_id == lease_id)
        .values(status=LeaseStatus.REVOKED.value, revoked_at=datetime.utcnow())
    )
    await db.commit()


async def list_leases(
    db: AsyncSession,
    client_id: Optional[str] = None,
    secret_name: Optional[str] = None,
    active_only: bool = True,
) -> List[SecretLease]:
    stmt = select(SecretLease)
    if client_id:
        stmt = stmt.where(SecretLease.client_id == client_id)
    if secret_name:
        stmt = stmt.where(SecretLease.secret_name == secret_name)
    if active_only:
        stmt = stmt.where(
            SecretLease.status == LeaseStatus.ACTIVE.value,
            SecretLease.expires_at > datetime.utcnow(),
        )
    result = await db.execute(stmt.order_by(SecretLease.issued_at.desc()))
    return result.scalars().all()
