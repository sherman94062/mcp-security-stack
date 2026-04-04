"""
Admin API for managing the gateway:
  - Register / deactivate backend MCP servers
  - Create / list / delete access policies
  - Health-check all registered backends
"""

import asyncio
from typing import List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from ..storage import (
    get_db, register_server, list_servers, get_server,
    create_policy, list_policies, deactivate_policy,
)
from ..models import (
    ServerRegistration, ServerResponse,
    PolicyCreate, PolicyResponse,
)
from ..proxy import check_backend_health
from ..config import gateway_settings

router = APIRouter(prefix="/admin", tags=["Admin"])


def _require_admin(x_admin_key: str = Header(...)):
    if x_admin_key != gateway_settings.GATEWAY_ADMIN_KEY:
        raise HTTPException(status_code=401, detail="Invalid admin key")


# ── Server Registry ───────────────────────────────────────────────────────────

@router.post("/servers", response_model=ServerResponse, status_code=201)
async def add_server(
    data: ServerRegistration,
    db: AsyncSession = Depends(get_db),
    _auth = Depends(_require_admin),
):
    """
    Register a backend MCP server with the gateway.
    Subsequent tool calls to /gateway/{server_id}/tools/* will be proxied here.
    """
    server = await register_server(db, data)
    return server


@router.get("/servers", response_model=List[ServerResponse])
async def get_servers(
    db: AsyncSession = Depends(get_db),
    _auth = Depends(_require_admin),
):
    """List all registered backend MCP servers."""
    return await list_servers(db)


@router.get("/servers/{server_id}/health")
async def server_health(
    server_id: str,
    db: AsyncSession = Depends(get_db),
    _auth = Depends(_require_admin),
):
    """Probe a backend MCP server's health endpoint."""
    server = await get_server(db, server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    health_url = server.health_url or f"{server.base_url}/health"
    healthy = await check_backend_health(health_url)

    return {
        "server_id": server_id,
        "base_url":  server.base_url,
        "healthy":   healthy,
        "health_url": health_url,
    }


@router.get("/servers/health/all")
async def all_servers_health(
    db: AsyncSession = Depends(get_db),
    _auth = Depends(_require_admin),
):
    """Probe all registered backends concurrently."""
    servers = await list_servers(db)

    async def probe(server):
        url = server.health_url or f"{server.base_url}/health"
        healthy = await check_backend_health(url)
        return {"server_id": server.server_id, "healthy": healthy, "url": url}

    results = await asyncio.gather(*[probe(s) for s in servers])
    return {"servers": results, "total": len(results)}


# ── Policy Management ─────────────────────────────────────────────────────────

@router.post("/policies", response_model=PolicyResponse, status_code=201)
async def add_policy(
    data: PolicyCreate,
    db: AsyncSession = Depends(get_db),
    _auth = Depends(_require_admin),
):
    """
    Create an access policy.

    Examples:

    Allow all tools on payments-server for the AML agent:
        { "client_id": "aml-agent", "server_id": "payments-server",
          "allowed_tools": ["*"], "rate_limit_rpm": 30 }

    Allow only get_balance, deny transfer_funds for a read-only agent:
        { "client_id": "reporting-agent", "server_id": "payments-server",
          "allowed_tools": ["get_balance", "get_transaction_history"] }

    Global default deny for unknown clients (wildcard):
        { "client_id": "*", "server_id": "*",
          "allowed_tools": ["*"], "effect": "deny" }
    """
    policy = await create_policy(db, data)
    import json
    return PolicyResponse(
        policy_id=policy.policy_id,
        client_id=policy.client_id,
        server_id=policy.server_id,
        allowed_tools=json.loads(policy.allowed_tools),
        effect=policy.effect,
        rate_limit_rpm=policy.rate_limit_rpm,
        rate_limit_rpd=policy.rate_limit_rpd,
        is_active=policy.is_active,
        created_at=policy.created_at,
        notes=policy.notes,
    )


@router.get("/policies", response_model=List[PolicyResponse])
async def get_policies(
    client_id: Optional[str] = Query(default=None),
    db: AsyncSession = Depends(get_db),
    _auth = Depends(_require_admin),
):
    """List policies, optionally filtered by client_id."""
    import json
    policies = await list_policies(db, client_id=client_id)
    return [
        PolicyResponse(
            policy_id=p.policy_id,
            client_id=p.client_id,
            server_id=p.server_id,
            allowed_tools=json.loads(p.allowed_tools),
            effect=p.effect,
            rate_limit_rpm=p.rate_limit_rpm,
            rate_limit_rpd=p.rate_limit_rpd,
            is_active=p.is_active,
            created_at=p.created_at,
            notes=p.notes,
        )
        for p in policies
    ]


@router.delete("/policies/{policy_id}", status_code=204)
async def delete_policy(
    policy_id: str,
    db: AsyncSession = Depends(get_db),
    _auth = Depends(_require_admin),
):
    """Deactivate a policy (soft delete)."""
    await deactivate_policy(db, policy_id)
