import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum

from pydantic import BaseModel, Field
from sqlalchemy import Column, String, Boolean, DateTime, Text, Integer, Float, Index
from sqlalchemy.orm import DeclarativeBase


# ── Enums ──────────────────────────────────────────────────────────────────────

class PolicyEffect(str, Enum):
    ALLOW = "allow"
    DENY  = "deny"


class RateLimitWindow(str, Enum):
    MINUTE = "minute"
    HOUR   = "hour"
    DAY    = "day"


# ── SQLAlchemy ORM ─────────────────────────────────────────────────────────────

class Base(DeclarativeBase):
    pass


class MCPServer(Base):
    """
    Registered backend MCP servers.
    The gateway proxies to these based on the request path.
    """
    __tablename__ = "mcp_servers"

    server_id    = Column(String, primary_key=True)          # e.g. "payments-server"
    display_name = Column(String, nullable=False)
    base_url     = Column(String, nullable=False)            # e.g. "http://payments-mcp:9000"
    description  = Column(Text,   nullable=True)
    is_active    = Column(Boolean, default=True)
    health_url   = Column(String, nullable=True)             # Optional /health path
    created_at   = Column(DateTime, default=datetime.utcnow)
    last_seen_at = Column(DateTime, nullable=True)


class Policy(Base):
    """
    Per-client (or wildcard) access policy.
    Controls which servers and tools a client can call.
    """
    __tablename__ = "policies"

    policy_id    = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    # client_id="*" means this is a default/fallback policy
    client_id    = Column(String, nullable=False, index=True)
    server_id    = Column(String, nullable=False, index=True)  # "*" = all servers
    # JSON array of tool names, e.g. ["transfer_funds", "get_balance"]
    # "*" as single element means all tools on this server
    allowed_tools = Column(Text, nullable=False, default='["*"]')
    effect       = Column(String, nullable=False, default=PolicyEffect.ALLOW)
    # Rate limits for this client+server combination
    rate_limit_rpm = Column(Integer, nullable=True)   # Per-minute limit
    rate_limit_rpd = Column(Integer, nullable=True)   # Per-day limit
    is_active    = Column(Boolean, default=True)
    created_at   = Column(DateTime, default=datetime.utcnow)
    notes        = Column(Text, nullable=True)

    __table_args__ = (
        Index("ix_policy_client_server", "client_id", "server_id"),
    )


class RateLimitCounter(Base):
    """
    Sliding window rate limit counters per client+server.
    """
    __tablename__ = "rate_limit_counters"

    counter_id  = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    client_id   = Column(String, nullable=False, index=True)
    server_id   = Column(String, nullable=False)
    window      = Column(String, nullable=False)   # minute / hour / day
    window_key  = Column(String, nullable=False)   # "2026-04-03T14:05" for minute window
    count       = Column(Integer, default=0)
    updated_at  = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_ratelimit_client_window", "client_id", "server_id", "window", "window_key"),
    )


# ── Pydantic schemas ───────────────────────────────────────────────────────────

class ServerRegistration(BaseModel):
    server_id:    str = Field(..., pattern=r"^[a-z0-9\-]+$")
    display_name: str
    base_url:     str
    description:  Optional[str] = None
    health_url:   Optional[str] = None


class ServerResponse(BaseModel):
    server_id:    str
    display_name: str
    base_url:     str
    description:  Optional[str]
    is_active:    bool
    health_url:   Optional[str]
    created_at:   datetime

    class Config:
        from_attributes = True


class PolicyCreate(BaseModel):
    client_id:       str
    server_id:       str
    allowed_tools:   List[str] = ["*"]
    effect:          PolicyEffect = PolicyEffect.ALLOW
    rate_limit_rpm:  Optional[int] = None
    rate_limit_rpd:  Optional[int] = None
    notes:           Optional[str] = None


class PolicyResponse(BaseModel):
    policy_id:       str
    client_id:       str
    server_id:       str
    allowed_tools:   List[str]
    effect:          str
    rate_limit_rpm:  Optional[int]
    rate_limit_rpd:  Optional[int]
    is_active:       bool
    created_at:      datetime
    notes:           Optional[str]

    class Config:
        from_attributes = True


class PolicyDecision(BaseModel):
    """Result of evaluating a request against policies."""
    allowed:         bool
    reason:          str
    policy_id:       Optional[str] = None
    rate_limited:    bool = False
    remaining_rpm:   Optional[int] = None
    remaining_rpd:   Optional[int] = None


class ProxyRequest(BaseModel):
    """Structured MCP tool invocation."""
    tool_name:  str
    tool_input: Dict[str, Any] = {}
    session_id: Optional[str] = None
    trace_id:   Optional[str] = None


class ProxyResponse(BaseModel):
    tool_output:  Any
    duration_ms:  float
    server_id:    str
    tool_name:    str
    trace_id:     Optional[str]
