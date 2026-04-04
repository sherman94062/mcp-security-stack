"""Admin endpoints for access policies and backend health checks."""

from typing import List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from ..storage import (
    get_db, create_access_policy, list_access_policies, deactivate_access_policy,
)
from ..models import AccessPolicyCreate, AccessPolicyResponse
from ..backends import get_backend
from ..backends.local import LocalBackend
from ..config import secrets_settings

router = APIRouter(prefix="/admin", tags=["Admin"])


def _require_admin(x_admin_key: str = Header(...)):
    if x_admin_key != secrets_settings.SECRETS_ADMIN_KEY:
        raise HTTPException(status_code=401, detail="Invalid admin key")


# ── Access policies ───────────────────────────────────────────────────────────

@router.post("/policies", response_model=AccessPolicyResponse, status_code=201)
async def add_policy(
    data: AccessPolicyCreate,
    db: AsyncSession = Depends(get_db),
    _auth=Depends(_require_admin),
):
    """
    Grant a client access to secrets matching a pattern.

    Examples:
        Grant the AML agent access to all payments secrets:
            { "client_id": "aml-agent", "secret_pattern": "payments/*",
              "max_lease_ttl": 300 }

        Grant the FX agent access to a specific key only:
            { "client_id": "fx-agent", "secret_pattern": "fx/open-exchange-key" }

        Grant all clients access to a shared public config (not really a secret):
            { "client_id": "*", "secret_pattern": "config/public-*" }
    """
    return await create_access_policy(db, data)


@router.get("/policies", response_model=List[AccessPolicyResponse])
async def get_policies(
    client_id: Optional[str] = Query(default=None),
    db: AsyncSession = Depends(get_db),
    _auth=Depends(_require_admin),
):
    return await list_access_policies(db, client_id=client_id)


@router.delete("/policies/{policy_id}", status_code=204)
async def delete_policy(
    policy_id: str,
    db: AsyncSession = Depends(get_db),
    _auth=Depends(_require_admin),
):
    await deactivate_access_policy(db, policy_id)


# ── Backend health checks ─────────────────────────────────────────────────────

@router.get("/backends/health")
async def backend_health(_auth=Depends(_require_admin)):
    """Check connectivity to all configured secret backends."""
    results = {}

    results["local"] = {"healthy": True, "note": "Always available"}

    vault_configured = bool(secrets_settings.VAULT_ADDR)
    if vault_configured:
        vault = get_backend("vault")
        results["vault"] = {
            "healthy": await vault.health_check(),
            "addr": secrets_settings.VAULT_ADDR,
        }
    else:
        results["vault"] = {"healthy": False, "note": "Not configured (VAULT_ADDR not set)"}

    aws_configured = bool(secrets_settings.AWS_REGION)
    if aws_configured:
        aws = get_backend("aws")
        results["aws"] = {
            "healthy": await aws.health_check(),
            "region": secrets_settings.AWS_REGION,
        }
    else:
        results["aws"] = {"healthy": False, "note": "Not configured (AWS_REGION not set)"}

    gcp_configured = bool(secrets_settings.GCP_PROJECT_ID)
    if gcp_configured:
        gcp = get_backend("gcp")
        results["gcp"] = {
            "healthy": await gcp.health_check(),
            "project": secrets_settings.GCP_PROJECT_ID,
        }
    else:
        results["gcp"] = {"healthy": False, "note": "Not configured (GCP_PROJECT_ID not set)"}

    return {"backends": results}
