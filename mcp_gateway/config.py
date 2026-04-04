from pydantic_settings import BaseSettings
from typing import Optional


class GatewaySettings(BaseSettings):
    HOST: str = "0.0.0.0"
    GATEWAY_PORT: int = 8082
    BASE_URL: str = "http://localhost:8082"

    DATABASE_URL: str = "sqlite+aiosqlite:///./mcp_gateway.db"

    # Admin API key — used to register servers and manage policies
    GATEWAY_ADMIN_KEY: str = "dev-admin-key-change-in-production"

    # OAuth server — gateway introspects every bearer token here
    OAUTH_SERVER_URL: str = "http://localhost:8080"
    OAUTH_CLIENT_ID: str = ""       # Gateway's own OAuth client_id
    OAUTH_CLIENT_SECRET: str = ""   # Gateway's own OAuth client_secret

    # Audit server — gateway posts every tool call here
    AUDIT_SERVER_URL: str = "http://localhost:8081"
    AUDIT_INGEST_KEY: str = "dev-audit-key-change-in-production"

    # Global rate limit defaults (overridden per-client in policy)
    DEFAULT_RATE_LIMIT_RPM: int = 60       # Requests per minute
    DEFAULT_RATE_LIMIT_RPD: int = 10000    # Requests per day

    # Proxy timeouts
    BACKEND_TIMEOUT_SECONDS: float = 30.0

    class Config:
        env_file = ".env"
        extra = "ignore"


gateway_settings = GatewaySettings()
