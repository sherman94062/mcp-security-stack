from pydantic_settings import BaseSettings
from typing import Optional


class SecretsSettings(BaseSettings):
    HOST: str = "0.0.0.0"
    SECRETS_PORT: int = 8083
    BASE_URL: str = "http://localhost:8083"

    DATABASE_URL: str = "sqlite+aiosqlite:///./mcp_secrets.db"

    # Master encryption key for local secrets at rest (Fernet / AES-128-CBC)
    # Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    MASTER_ENCRYPTION_KEY: str = "dev-key-replace-with-fernet-key-in-production"

    # Admin key — manages secret definitions and access policies
    SECRETS_ADMIN_KEY: str = "dev-secrets-admin-change-in-production"

    # MCP server ingest key — MCP servers use this to request leases
    SECRETS_INGEST_KEY: str = "dev-secrets-ingest-change-in-production"

    # Default lease duration (MCP servers get secret values for this long)
    DEFAULT_LEASE_TTL_SECONDS: int = 300     # 5 minutes
    MAX_LEASE_TTL_SECONDS: int = 3600        # 1 hour hard ceiling

    # ── HashiCorp Vault (optional) ────────────────────────────────────────────
    VAULT_ADDR: Optional[str] = None         # e.g. "http://vault:8200"
    VAULT_TOKEN: Optional[str] = None
    VAULT_NAMESPACE: Optional[str] = None    # Vault Enterprise only
    VAULT_MOUNT: str = "secret"              # KV mount path

    # ── AWS Secrets Manager (optional) ────────────────────────────────────────
    AWS_REGION: Optional[str] = None         # e.g. "us-east-1"
    AWS_ACCESS_KEY_ID: Optional[str] = None
    AWS_SECRET_ACCESS_KEY: Optional[str] = None

    # ── GCP Secret Manager (optional) ─────────────────────────────────────────
    GCP_PROJECT_ID: Optional[str] = None
    GOOGLE_APPLICATION_CREDENTIALS: Optional[str] = None

    # ── Audit server integration ──────────────────────────────────────────────
    AUDIT_SERVER_URL: str = "http://localhost:8081"
    AUDIT_INGEST_KEY: str = "dev-audit-key-change-in-production"

    class Config:
        env_file = ".env"
        extra = "ignore"


secrets_settings = SecretsSettings()
