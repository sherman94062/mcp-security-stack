"""Admin endpoints for managing secret definitions."""

from typing import List
from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from ..storage import (
    get_db, create_secret, list_secrets,
    get_secret_by_id, deactivate_secret, rotate_secret,
)
from ..models import SecretCreate, SecretResponse, SecretRotate, SecretBackend
from ..backends import get_backend
from ..crypto import encrypt_secret
from ..config import secrets_settings

router = APIRouter(prefix="/secrets", tags=["Secret Definitions"])


def _require_admin(x_admin_key: str = Header(...)):
    if x_admin_key != secrets_settings.SECRETS_ADMIN_KEY:
        raise HTTPException(status_code=401, detail="Invalid admin key")


@router.post("", response_model=SecretResponse, status_code=201)
async def add_secret(
    data: SecretCreate,
    db: AsyncSession = Depends(get_db),
    _auth=Depends(_require_admin),
):
    """
    Register a secret definition.

    LOCAL backend: supply value= and it is encrypted at rest.
    Vault/AWS/GCP backends: supply backend_path= pointing to the external path.
      The secret value lives in the external system — this server never stores it.
    """
    if data.backend == SecretBackend.LOCAL:
        if not data.value:
            raise HTTPException(status_code=400, detail="value is required for local backend")
        # Encrypt and attach before saving
        data = data.model_copy(update={"encrypted_value": encrypt_secret(data.value)})
    else:
        if not data.backend_path:
            raise HTTPException(
                status_code=400,
                detail=f"backend_path is required for {data.backend} backend"
            )
        # Optionally write the value to the external backend now
        if data.value:
            backend = get_backend(data.backend)
            await backend.put_secret(data.backend_path, data.value)

    secret = await create_secret(db, data)
    return secret


@router.get("", response_model=List[SecretResponse])
async def get_secrets(
    db: AsyncSession = Depends(get_db),
    _auth=Depends(_require_admin),
):
    """List all registered secret definitions (no values returned)."""
    return await list_secrets(db)


@router.delete("/{secret_id}", status_code=204)
async def delete_secret(
    secret_id: str,
    db: AsyncSession = Depends(get_db),
    _auth=Depends(_require_admin),
):
    """Deactivate a secret definition (soft delete)."""
    await deactivate_secret(db, secret_id)


@router.post("/{secret_id}/rotate", response_model=SecretResponse)
async def rotate(
    secret_id: str,
    data: SecretRotate,
    db: AsyncSession = Depends(get_db),
    _auth=Depends(_require_admin),
):
    """
    Rotate a secret's value.
    For LOCAL backend: encrypts the new value.
    For external backends: writes the new value to the backend system.
    Existing leases are NOT automatically revoked — they expire naturally.
    Call DELETE /leases/{lease_id} to force-revoke outstanding leases after rotation.
    """
    secret = await get_secret_by_id(db, secret_id)
    if not secret:
        raise HTTPException(status_code=404, detail="Secret not found")

    if secret.backend == SecretBackend.LOCAL.value:
        new_encrypted = encrypt_secret(data.new_value)
        updated = await rotate_secret(db, secret_id, new_encrypted)
    else:
        backend = get_backend(secret.backend)
        path = data.backend_path or secret.backend_path
        await backend.put_secret(path, data.new_value)
        updated = await rotate_secret(db, secret_id, "")

    return updated
