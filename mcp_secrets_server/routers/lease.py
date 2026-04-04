"""
Lease endpoints — the primary interface for MCP servers.

An MCP server requests a lease for a secret it needs at runtime.
The response contains the actual secret value and a lease_id.
The lease expires after TTL seconds — the MCP server must re-request.
"""

import asyncio
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from ..storage import (
    get_db, get_secret_by_name, check_access,
    create_lease, get_lease, revoke_lease, list_leases,
)
from ..models import LeaseRequest, LeaseResponse, LeaseInfo, LeaseStatus
from ..backends import get_backend
from ..backends.local import LocalBackend
from ..audit_client import log_secret_access
from ..config import secrets_settings

router = APIRouter(prefix="/leases", tags=["Secret Leases"])


def _require_ingest_key(x_secrets_key: str = Header(...)):
    if x_secrets_key != secrets_settings.SECRETS_INGEST_KEY:
        raise HTTPException(status_code=401, detail="Invalid secrets key")

def _require_admin(x_admin_key: str = Header(...)):
    if x_admin_key != secrets_settings.SECRETS_ADMIN_KEY:
        raise HTTPException(status_code=401, detail="Invalid admin key")


@router.post("", response_model=LeaseResponse, status_code=201)
async def request_lease(
    payload: LeaseRequest,
    request: Request,
    x_mcp_client_id: str = Header(...),
    x_mcp_user_id: Optional[str] = Header(default=None),
    db: AsyncSession = Depends(get_db),
    _auth=Depends(_require_ingest_key),
):
    """
    MCP servers call this to get a secret value at runtime.

    The server sends:
        x-mcp-client-id: aml-agent
        x-secrets-key: <ingest key>

        { "secret_name": "stripe-api-key", "ttl_seconds": 300,
          "purpose": "Processing payment for transaction tx_001" }

    The response contains the actual secret value and a lease_id.
    The value is only ever returned here — never stored in logs.
    """
    client_id = x_mcp_client_id
    caller_ip = request.client.host if request.client else None

    # ── 1. Load secret definition ─────────────────────────────────────────────
    secret = await get_secret_by_name(db, payload.secret_name)
    if not secret:
        asyncio.create_task(log_secret_access(
            client_id=client_id, secret_name=payload.secret_name,
            action="lease_requested", outcome="error",
            trace_id=payload.trace_id, caller_ip=caller_ip,
            error_message="Secret not found",
        ))
        raise HTTPException(status_code=404, detail="Secret not found")

    # ── 2. Access control check ───────────────────────────────────────────────
    allowed, max_ttl = await check_access(db, client_id, payload.secret_name)
    if not allowed:
        asyncio.create_task(log_secret_access(
            client_id=client_id, secret_name=payload.secret_name,
            action="lease_requested", outcome="denied",
            trace_id=payload.trace_id, caller_ip=caller_ip,
            error_message=f"No access policy for {client_id} → {payload.secret_name}",
        ))
        raise HTTPException(
            status_code=403,
            detail=f"Client '{client_id}' is not permitted to access '{payload.secret_name}'"
        )

    # ── 3. Calculate TTL (respect policy cap) ─────────────────────────────────
    requested_ttl = payload.ttl_seconds or secrets_settings.DEFAULT_LEASE_TTL_SECONDS
    policy_cap    = max_ttl or secrets_settings.MAX_LEASE_TTL_SECONDS
    server_cap    = secrets_settings.MAX_LEASE_TTL_SECONDS
    ttl = min(requested_ttl, policy_cap, server_cap)

    # ── 4. Retrieve secret value from backend ─────────────────────────────────
    backend = get_backend(secret.backend)
    try:
        if isinstance(backend, LocalBackend):
            value = await backend.get_secret(secret.encrypted_value)
        else:
            value = await backend.get_secret(secret.backend_path)
    except Exception as exc:
        asyncio.create_task(log_secret_access(
            client_id=client_id, secret_name=payload.secret_name,
            action="lease_requested", outcome="error",
            trace_id=payload.trace_id, caller_ip=caller_ip,
            error_message=str(exc),
        ))
        raise HTTPException(status_code=502, detail=f"Backend error: {exc}")

    # ── 5. Create lease record ────────────────────────────────────────────────
    lease = await create_lease(
        db=db,
        secret=secret,
        client_id=client_id,
        ttl_seconds=ttl,
        user_id=x_mcp_user_id,
        trace_id=payload.trace_id,
        caller_ip=caller_ip,
        purpose=payload.purpose,
    )

    asyncio.create_task(log_secret_access(
        client_id=client_id, secret_name=payload.secret_name,
        action="lease_issued", outcome="success",
        user_id=x_mcp_user_id, trace_id=payload.trace_id,
        caller_ip=caller_ip, lease_id=lease.lease_id,
    ))

    return LeaseResponse(
        lease_id=lease.lease_id,
        secret_name=secret.name,
        secret_value=value,        # Only time value is returned
        issued_at=lease.issued_at,
        expires_at=lease.expires_at,
        ttl_seconds=ttl,
        backend=secret.backend,
    )


@router.delete("/{lease_id}", status_code=204)
async def revoke(
    lease_id: str,
    db: AsyncSession = Depends(get_db),
    _auth=Depends(_require_admin),
):
    """
    Force-revoke a lease. Use after secret rotation to invalidate outstanding grants.
    """
    lease = await get_lease(db, lease_id)
    if not lease:
        raise HTTPException(status_code=404, detail="Lease not found")
    await revoke_lease(db, lease_id)
    asyncio.create_task(log_secret_access(
        client_id=lease.client_id, secret_name=lease.secret_name,
        action="lease_revoked", outcome="success",
        lease_id=lease_id,
    ))


@router.get("", response_model=List[LeaseInfo])
async def get_leases(
    client_id: Optional[str] = None,
    secret_name: Optional[str] = None,
    active_only: bool = True,
    db: AsyncSession = Depends(get_db),
    _auth=Depends(_require_admin),
):
    """List leases for audit/compliance review. Never returns secret values."""
    return await list_leases(db, client_id=client_id, secret_name=secret_name, active_only=active_only)
