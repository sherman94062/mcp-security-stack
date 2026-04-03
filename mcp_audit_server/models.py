import uuid
from datetime import datetime
from typing import Optional, Any, Dict, List
from enum import Enum

from pydantic import BaseModel, Field
from sqlalchemy import Column, String, Boolean, DateTime, Text, Integer, Float, Index
from sqlalchemy.orm import DeclarativeBase


# ── Enums ─────────────────────────────────────────────────────────────────────

class EventOutcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED  = "denied"    # Auth/policy rejection
    TIMEOUT = "timeout"
    ERROR   = "error"


class EventSeverity(str, Enum):
    INFO     = "info"
    WARNING  = "warning"
    CRITICAL = "critical"


# ── SQLAlchemy ORM ─────────────────────────────────────────────────────────────

class Base(DeclarativeBase):
    pass


class AuditEvent(Base):
    """
    Immutable audit log of every MCP tool call.
    Rows are INSERT-only — no UPDATE, no DELETE.
    """
    __tablename__ = "audit_events"

    # Identity
    event_id     = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    created_at   = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    # Who
    client_id    = Column(String, nullable=False, index=True)   # OAuth client / agent ID
    user_id      = Column(String, nullable=True,  index=True)   # Human user if applicable
    agent_name   = Column(String, nullable=True)                # Friendly name of the agent

    # What
    mcp_server_id = Column(String, nullable=False, index=True)  # Which MCP server was called
    tool_name     = Column(String, nullable=False, index=True)  # Which tool was invoked
    tool_input    = Column(Text,   nullable=True)               # JSON — may be redacted
    tool_output   = Column(Text,   nullable=True)               # JSON — may be redacted
    input_redacted  = Column(Boolean, default=False)
    output_redacted = Column(Boolean, default=False)

    # How it went
    outcome       = Column(String, nullable=False, index=True)  # EventOutcome
    error_message = Column(Text,   nullable=True)
    duration_ms   = Column(Float,  nullable=True)               # Latency

    # Severity for SIEM triage
    severity      = Column(String, default=EventSeverity.INFO, index=True)

    # Network / runtime context
    caller_ip     = Column(String, nullable=True)
    trace_id      = Column(String, nullable=True, index=True)   # Distributed trace ID
    session_id    = Column(String, nullable=True, index=True)   # Conversation/session

    # Auth context
    token_scopes  = Column(Text,   nullable=True)               # Scopes on the token used
    policy_decision = Column(Text, nullable=True)               # Why allowed/denied

    __table_args__ = (
        Index("ix_audit_client_tool", "client_id", "tool_name"),
        Index("ix_audit_server_tool", "mcp_server_id", "tool_name"),
        Index("ix_audit_created_outcome", "created_at", "outcome"),
    )


# ── Pydantic schemas ───────────────────────────────────────────────────────────

class AuditEventCreate(BaseModel):
    """Payload MCP servers POST to the audit server after each tool call."""
    client_id:     str
    user_id:       Optional[str] = None
    agent_name:    Optional[str] = None

    mcp_server_id: str
    tool_name:     str
    tool_input:    Optional[Dict[str, Any]] = None
    tool_output:   Optional[Any] = None

    outcome:       EventOutcome
    error_message: Optional[str] = None
    duration_ms:   Optional[float] = None
    severity:      EventSeverity = EventSeverity.INFO

    caller_ip:     Optional[str] = None
    trace_id:      Optional[str] = None
    session_id:    Optional[str] = None
    token_scopes:  Optional[List[str]] = None
    policy_decision: Optional[str] = None


class AuditEventResponse(BaseModel):
    event_id:      str
    created_at:    datetime
    client_id:     str
    user_id:       Optional[str]
    agent_name:    Optional[str]
    mcp_server_id: str
    tool_name:     str
    tool_input:    Optional[Any]
    tool_output:   Optional[Any]
    input_redacted:  bool
    output_redacted: bool
    outcome:       str
    error_message: Optional[str]
    duration_ms:   Optional[float]
    severity:      str
    caller_ip:     Optional[str]
    trace_id:      Optional[str]
    session_id:    Optional[str]
    token_scopes:  Optional[List[str]]
    policy_decision: Optional[str]

    class Config:
        from_attributes = True


class AuditQueryParams(BaseModel):
    client_id:     Optional[str] = None
    user_id:       Optional[str] = None
    mcp_server_id: Optional[str] = None
    tool_name:     Optional[str] = None
    outcome:       Optional[EventOutcome] = None
    severity:      Optional[EventSeverity] = None
    trace_id:      Optional[str] = None
    session_id:    Optional[str] = None
    from_ts:       Optional[datetime] = None
    to_ts:         Optional[datetime] = None
    limit:         int = Field(default=100, le=1000)
    offset:        int = 0


class AuditSummary(BaseModel):
    total_events:    int
    success_count:   int
    failure_count:   int
    denied_count:    int
    error_count:     int
    top_tools:       List[Dict[str, Any]]
    top_clients:     List[Dict[str, Any]]
    avg_duration_ms: Optional[float]
    period_start:    Optional[datetime]
    period_end:      Optional[datetime]
