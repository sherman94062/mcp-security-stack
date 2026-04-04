"""
HashiCorp Vault KV v2 backend.

Requires:
    pip install hvac

Configure via environment:
    VAULT_ADDR=http://vault:8200
    VAULT_TOKEN=s.xxxxx
    VAULT_MOUNT=secret          # KV mount path
    VAULT_NAMESPACE=            # Enterprise only
"""

import logging
from typing import Optional
from .base import SecretBackendBase
from ..config import secrets_settings

logger = logging.getLogger("mcp_secrets.vault")


class VaultBackend(SecretBackendBase):

    def __init__(self):
        self._client = None

    def _get_client(self):
        if self._client is not None:
            return self._client
        try:
            import hvac
        except ImportError:
            raise RuntimeError(
                "hvac is required for Vault backend. Install with: pip install hvac"
            )

        if not secrets_settings.VAULT_ADDR or not secrets_settings.VAULT_TOKEN:
            raise RuntimeError("VAULT_ADDR and VAULT_TOKEN must be set for Vault backend")

        self._client = hvac.Client(
            url=secrets_settings.VAULT_ADDR,
            token=secrets_settings.VAULT_TOKEN,
            namespace=secrets_settings.VAULT_NAMESPACE,
        )
        return self._client

    async def get_secret(self, path: str) -> str:
        """
        Read a secret from Vault KV v2.
        Path format: "payments/stripe-api-key"
        Vault path becomes: secret/data/payments/stripe-api-key
        The secret is expected to have a "value" key.
        """
        client = self._get_client()
        mount = secrets_settings.VAULT_MOUNT
        try:
            response = client.secrets.kv.v2.read_secret_version(
                path=path, mount_point=mount
            )
            data = response["data"]["data"]
            if "value" not in data:
                raise ValueError(
                    f"Vault secret at {path} has no 'value' key. "
                    f"Available keys: {list(data.keys())}"
                )
            return data["value"]
        except Exception as exc:
            logger.error("Vault get_secret failed for path %s: %s", path, exc)
            raise ValueError(f"Could not retrieve secret from Vault: {exc}") from exc

    async def put_secret(self, path: str, value: str) -> None:
        client = self._get_client()
        mount = secrets_settings.VAULT_MOUNT
        try:
            client.secrets.kv.v2.create_or_update_secret(
                path=path,
                secret={"value": value},
                mount_point=mount,
            )
        except Exception as exc:
            logger.error("Vault put_secret failed for path %s: %s", path, exc)
            raise ValueError(f"Could not write secret to Vault: {exc}") from exc

    async def delete_secret(self, path: str) -> None:
        client = self._get_client()
        mount = secrets_settings.VAULT_MOUNT
        try:
            client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=path, mount_point=mount
            )
        except Exception as exc:
            logger.error("Vault delete_secret failed for path %s: %s", path, exc)

    async def health_check(self) -> bool:
        try:
            client = self._get_client()
            return client.sys.is_initialized()
        except Exception:
            return False


vault_backend = VaultBackend()
