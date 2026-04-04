"""
LOCAL backend: encrypted values stored in the SQLite database.
Intended for local dev and testing. In production use Vault, AWS, or GCP.
"""

from .base import SecretBackendBase
from ..crypto import encrypt_secret, decrypt_secret


# In-memory store for the local backend (backed by the SecretDefinition ORM rows)
# The actual I/O goes through the storage layer; this class handles crypto only.

class LocalBackend(SecretBackendBase):
    """
    Wraps the crypto layer. Actual persistence is handled by storage.py —
    this backend is called by the lease router after the ORM row is loaded.
    """

    async def get_secret(self, encrypted_value: str) -> str:
        """Decrypt and return the local secret value."""
        if not encrypted_value:
            raise ValueError("No encrypted value stored for this local secret")
        return decrypt_secret(encrypted_value)

    async def put_secret(self, path: str, value: str) -> str:
        """Encrypt a new value. Returns the ciphertext for storage."""
        return encrypt_secret(value)

    async def delete_secret(self, path: str) -> None:
        pass  # Deletion handled by storage layer

    async def health_check(self) -> bool:
        return True


local_backend = LocalBackend()
