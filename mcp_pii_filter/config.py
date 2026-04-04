from pydantic_settings import BaseSettings
from typing import List


class PIIFilterSettings(BaseSettings):
    HOST: str = "0.0.0.0"
    PII_PORT: int = 8084
    BASE_URL: str = "http://localhost:8084"

    DATABASE_URL: str = "sqlite+aiosqlite:///./mcp_pii.db"

    # API keys
    PII_ADMIN_KEY: str = "dev-pii-admin-change-in-production"
    PII_FILTER_KEY: str = "dev-pii-filter-change-in-production"

    # Default redaction strategy: REDACT | MASK | HASH | FLAG
    DEFAULT_STRATEGY: str = "REDACT"

    # PII types enabled by default (all). Can disable per-rule.
    DEFAULT_ENABLED_TYPES: List[str] = [
        "EMAIL", "PHONE", "CREDIT_CARD", "SSN", "IBAN",
        "BANK_ACCOUNT", "CRYPTO_BTC", "CRYPTO_ETH", "CRYPTO_SOL",
        "IP_ADDRESS", "DATE_OF_BIRTH", "PASSPORT", "NATIONAL_ID",
        "PERSON_NAME", "URL_WITH_PII",
    ]

    # Audit server
    AUDIT_SERVER_URL: str = "http://localhost:8081"
    AUDIT_INGEST_KEY: str = "dev-audit-key-change-in-production"

    class Config:
        env_file = ".env"
        extra = "ignore"


pii_settings = PIIFilterSettings()
