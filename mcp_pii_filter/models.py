import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum

from pydantic import BaseModel, Field
from sqlalchemy import Column, String, Boolean, DateTime, Text, Integer, Index
from sqlalchemy.orm import DeclarativeBase


# ── Enums ──────────────────────────────────────────────────────────────────────

class PIIType(str, Enum):
    EMAIL          = "EMAIL"
    PHONE          = "PHONE"
    CREDIT_CARD    = "CREDIT_CARD"
    SSN            = "SSN"
    IBAN           = "IBAN"
    BANK_ACCOUNT   = "BANK_ACCOUNT"
    CRYPTO_BTC     = "CRYPTO_BTC"
    CRYPTO_ETH     = "CRYPTO_ETH"
    CRYPTO_SOL     = "CRYPTO_SOL"
    IP_ADDRESS     = "IP_ADDRESS"
    DATE_OF_BIRTH  = "DATE_OF_BIRTH"
    PASSPORT       = "PASSPORT"
    NATIONAL_ID    = "NATIONAL_ID"
    PERSON_NAME    = "PERSON_NAME"
    URL_WITH_PII   = "URL_WITH_PII"


class RedactionStrategy(str, Enum):
    REDACT = "REDACT"   # Replace entirely: [REDACTED:EMAIL]
    MASK   = "MASK"     # Partial: show last 4 for cards, domain for email
    HASH   = "HASH"     # Consistent SHA-256 token (correlation without exposure)
    FLAG   = "FLAG"     # Leave value, add detection metadata only


class FilterAction(str, Enum):
    BLOCK  = "BLOCK"    # Reject the entire payload if PII found
    REDACT = "REDACT"   # Redact and allow through
    FLAG   = "FLAG"     # Pass through but annotate detections


# ── SQLAlchemy ORM ─────────────────────────────────────────────────────────────

class Base(DeclarativeBase):
    pass


class FilterRule(Base):
    """
    Per-server (or per-tool) filter configuration.
    Controls which PII types are detected and how they are handled.
    """
    __tablename__ = "filter_rules"

    rule_id        = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    # Target: "payments-server", "payments-server/transfer_funds", or "*"
    target         = Column(String, nullable=False, index=True)
    # Direction: "input", "output", or "both"
    direction      = Column(String, nullable=False, default="both")
    # JSON list of PIIType values to detect (empty = use defaults)
    enabled_types  = Column(Text, nullable=True)
    strategy       = Column(String, nullable=False, default=RedactionStrategy.REDACT)
    action         = Column(String, nullable=False, default=FilterAction.REDACT)
    # JSON list of field paths to skip (e.g. ["wallet_address"] for blockchain tools)
    field_allowlist = Column(Text, nullable=True)
    is_active      = Column(Boolean, default=True)
    created_at     = Column(DateTime, default=datetime.utcnow)
    notes          = Column(Text, nullable=True)

    __table_args__ = (Index("ix_rule_target", "target"),)


class PIIDetectionLog(Base):
    """
    Aggregate log of PII detections — never stores the actual PII value.
    Used for compliance reporting: "how much PII is flowing through which tools?"
    """
    __tablename__ = "pii_detection_logs"

    log_id         = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    detected_at    = Column(DateTime, default=datetime.utcnow, index=True)
    server_id      = Column(String, nullable=True, index=True)
    tool_name      = Column(String, nullable=True, index=True)
    client_id      = Column(String, nullable=True, index=True)
    direction      = Column(String, nullable=False)   # input | output
    pii_types_found = Column(Text, nullable=False)    # JSON list of PIIType values
    detection_count = Column(Integer, default=0)
    action_taken   = Column(String, nullable=False)
    trace_id       = Column(String, nullable=True, index=True)


# ── Pydantic schemas ───────────────────────────────────────────────────────────

class Detection(BaseModel):
    """A single PII detection hit."""
    pii_type:    PIIType
    field_path:  str             # JSON path where it was found: "body.sender_name"
    original:    Optional[str]   # Only populated in FLAG mode; None in REDACT/MASK/HASH
    redacted:    str             # The replacement value
    strategy:    RedactionStrategy


class FilterRequest(BaseModel):
    """Payload submitted to the filter API."""
    payload:      Dict[str, Any]        # The JSON to scan
    server_id:    Optional[str] = None
    tool_name:    Optional[str] = None
    client_id:    Optional[str] = None
    direction:    str = "input"         # "input" or "output"
    trace_id:     Optional[str] = None
    # Override rule lookup — apply these types directly
    override_types:    Optional[List[PIIType]] = None
    override_strategy: Optional[RedactionStrategy] = None
    override_action:   Optional[FilterAction] = None


class FilterResponse(BaseModel):
    """Result of running the PII filter."""
    clean_payload:   Dict[str, Any]     # Redacted/masked version
    detections:      List[Detection]    # What was found and replaced
    pii_found:       bool
    blocked:         bool               # True if action=BLOCK and PII was found
    detection_count: int
    trace_id:        Optional[str]


class FilterRuleCreate(BaseModel):
    target:          str = Field(..., description="server_id, server_id/tool_name, or *")
    direction:       str = "both"
    enabled_types:   Optional[List[PIIType]] = None
    strategy:        RedactionStrategy = RedactionStrategy.REDACT
    action:          FilterAction = FilterAction.REDACT
    field_allowlist: Optional[List[str]] = None
    notes:           Optional[str] = None


class FilterRuleResponse(BaseModel):
    rule_id:         str
    target:          str
    direction:       str
    enabled_types:   Optional[List[str]]
    strategy:        str
    action:          str
    field_allowlist: Optional[List[str]]
    is_active:       bool
    created_at:      datetime
    notes:           Optional[str]

    class Config:
        from_attributes = True


class PIISummary(BaseModel):
    total_scans:       int
    total_detections:  int
    by_type:           Dict[str, int]
    by_server:         Dict[str, int]
    by_tool:           Dict[str, int]
    period_start:      Optional[datetime]
    period_end:        Optional[datetime]
