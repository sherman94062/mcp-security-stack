from pydantic_settings import BaseSettings
from typing import Optional


class AuditSettings(BaseSettings):
    HOST: str = "0.0.0.0"
    AUDIT_PORT: int = 8081
    BASE_URL: str = "http://localhost:8081"

    DATABASE_URL: str = "sqlite+aiosqlite:///./mcp_audit.db"

    # API key required to write audit events (set on your MCP servers)
    AUDIT_INGEST_API_KEY: str = "dev-audit-key-change-in-production"

    # API key required to read/query audit events (set for compliance tooling)
    AUDIT_READ_API_KEY: str = "dev-read-key-change-in-production"

    # Webhook: forward events to a SIEM in real time (optional)
    SIEM_WEBHOOK_URL: Optional[str] = None
    SIEM_WEBHOOK_API_KEY: Optional[str] = None

    # Retention: events older than this many days can be archived (0 = keep forever)
    RETENTION_DAYS: int = 365

    class Config:
        env_file = ".env"
        extra = "ignore"


audit_settings = AuditSettings()
