import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum

from pydantic import BaseModel, Field
from sqlalchemy import Column, String, Boolean, DateTime, Text, Integer, Index
from sqlalchemy.orm import DeclarativeBase


# ── Enums ──────────────────────────────────────────────────────────────────────

class SecretBackend(str, Enum):
    LOCAL  = "local"     # Encrypted SQLite — dev/test
    VAULT  = "vault"     # HashiCorp Vault KV
    AWS    = "aws"       # AWS Secrets Manager
    GCP    = "gcp"       # GCP Secret Manager


class LeaseStatus(str, Enum):
    ACTIVE  = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


# ── SQLAlchemy ORM ─────────────────────────────────────────────────────────────

class Base(DeclarativeBase):
    pass


class SecretDefinition(Base):
    """
    Metadata about a secret. The actual value lives in the backend.
    For LOCAL backend, the encrypted value is stored in encrypted_value.
    """
    __tablename__ = "secret_definitions"

    secret_id     = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name          = Column(String, nullable=False, unique=True, index=True)
    description   = Column(Text, nullable=True)
    backend       = Column(String, nullable=False, default=SecretBackend.LOCAL)
    # For Vault/AWS/GCP: path/ARN/name in the backend system
    backend_path  = Column(String, nullable=True)
    # For LOCAL backend: AES-encrypted value stored here
    encrypted_value = Column(Text, nullable=True)
    # Comma-separated tags for grouping (e.g. "payments,stripe,prod")
    tags          = Column(Text, nullable=True)
    is_active     = Column(Boolean, default=True)
    created_at    = Column(DateTime, default=datetime.utcnow)
    rotated_at    = Column(DateTime, nullable=True)
    # Who created it
    created_by    = Column(String, nullable=True)


class AccessPolicy(Base):
    """
    Controls which client_ids can request leases for which secrets.
    Supports wildcard secret names (e.g. "payments/*").
    """
    __tablename__ = "secret_access_policies"

    policy_id     = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    client_id     = Column(String, nullable=False, index=True)
    # Secret name or pattern: "stripe-api-key", "payments/*", "*"
    secret_pattern = Column(String, nullable=False)
    # Max lease TTL this client may request (None = use server default)
    max_lease_ttl  = Column(Integer, nullable=True)
    is_active      = Column(Boolean, default=True)
    created_at     = Column(DateTime, default=datetime.utcnow)
    notes          = Column(Text, nullable=True)

    __table_args__ = (
        Index("ix_access_policy_client", "client_id", "secret_pattern"),
    )


class SecretLease(Base):
    """
    A time-limited grant for a client to access a secret value.
    Once issued, the secret value was delivered — lease tracks accountability.
    """
    __tablename__ = "secret_leases"

    lease_id      = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    secret_id     = Column(String, nullable=False, index=True)
    secret_name   = Column(String, nullable=False)
    client_id     = Column(String, nullable=False, index=True)
    user_id       = Column(String, nullable=True)
    status        = Column(String, nullable=False, default=LeaseStatus.ACTIVE)
    issued_at     = Column(DateTime, default=datetime.utcnow)
    expires_at    = Column(DateTime, nullable=False)
    revoked_at    = Column(DateTime, nullable=True)
    # Request context
    trace_id      = Column(String, nullable=True)
    caller_ip     = Column(String, nullable=True)
    purpose       = Column(Text, nullable=True)   # Human-readable reason for access

    __table_args__ = (
        Index("ix_lease_client_secret", "client_id", "secret_id"),
        Index("ix_lease_expires", "expires_at", "status"),
    )


# ── Pydantic schemas ───────────────────────────────────────────────────────────

class SecretCreate(BaseModel):
    name:          str = Field(..., pattern=r"^[a-zA-Z0-9\-_/]+$")
    description:   Optional[str] = None
    backend:       SecretBackend = SecretBackend.LOCAL
    backend_path:  Optional[str] = None   # Required for Vault/AWS/GCP
    value:         Optional[str] = None   # Required for LOCAL backend (stored encrypted)
    tags:          Optional[str] = None
    created_by:    Optional[str] = None


class SecretResponse(BaseModel):
    secret_id:    str
    name:         str
    description:  Optional[str]
    backend:      str
    backend_path: Optional[str]
    tags:         Optional[str]
    is_active:    bool
    created_at:   datetime
    rotated_at:   Optional[datetime]
    created_by:   Optional[str]
    # Never includes the value or encrypted_value

    class Config:
        from_attributes = True


class SecretRotate(BaseModel):
    new_value:    str
    backend_path: Optional[str] = None   # If changing backend path too


class AccessPolicyCreate(BaseModel):
    client_id:      str
    secret_pattern: str
    max_lease_ttl:  Optional[int] = None
    notes:          Optional[str] = None


class AccessPolicyResponse(BaseModel):
    policy_id:      str
    client_id:      str
    secret_pattern: str
    max_lease_ttl:  Optional[int]
    is_active:      bool
    created_at:     datetime
    notes:          Optional[str]

    class Config:
        from_attributes = True


class LeaseRequest(BaseModel):
    secret_name:  str
    ttl_seconds:  Optional[int] = None   # Requested TTL; capped at policy max
    purpose:      Optional[str] = None   # Why this secret is needed (audit trail)
    trace_id:     Optional[str] = None


class LeaseResponse(BaseModel):
    lease_id:     str
    secret_name:  str
    secret_value: str              # The actual decrypted secret — only returned here
    issued_at:    datetime
    expires_at:   datetime
    ttl_seconds:  int
    backend:      str


class LeaseInfo(BaseModel):
    lease_id:     str
    secret_name:  str
    client_id:    str
    status:       str
    issued_at:    datetime
    expires_at:   datetime
    purpose:      Optional[str]

    class Config:
        from_attributes = True
