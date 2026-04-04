"""
Encryption at rest for LOCAL backend secrets.

Uses Fernet (AES-128-CBC + HMAC-SHA256) from the cryptography library.
The master key is loaded from MASTER_ENCRYPTION_KEY env var.

For production, replace MASTER_ENCRYPTION_KEY with a key fetched from
your KMS (AWS KMS, GCP KMS, or HashiCorp Vault Transit) at startup —
never store the master key in plaintext on disk.
"""

import base64
import logging
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken

from .config import secrets_settings

logger = logging.getLogger("mcp_secrets.crypto")


@lru_cache(maxsize=1)
def _get_fernet() -> Fernet:
    key = secrets_settings.MASTER_ENCRYPTION_KEY

    # If it looks like a raw string (not base64 Fernet key), derive one
    if not _is_fernet_key(key):
        logger.warning(
            "MASTER_ENCRYPTION_KEY is not a valid Fernet key. "
            "Deriving one from it — set a proper Fernet key in production."
        )
        import hashlib
        raw = hashlib.sha256(key.encode()).digest()
        key = base64.urlsafe_b64encode(raw).decode()

    return Fernet(key.encode())


def _is_fernet_key(key: str) -> bool:
    try:
        decoded = base64.urlsafe_b64decode(key + "==")
        return len(decoded) == 32
    except Exception:
        return False


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a secret value. Returns a base64-encoded ciphertext string."""
    fernet = _get_fernet()
    return fernet.encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str) -> str:
    """Decrypt a secret value. Raises ValueError on tampered/invalid ciphertext."""
    fernet = _get_fernet()
    try:
        return fernet.decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        raise ValueError("Secret decryption failed — ciphertext is invalid or tampered") from exc


def generate_fernet_key() -> str:
    """Utility: generate a new Fernet key for MASTER_ENCRYPTION_KEY."""
    return Fernet.generate_key().decode()
