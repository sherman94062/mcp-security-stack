import uuid
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel
from sqlalchemy import Column, String, Boolean, DateTime, Text, Integer
from sqlalchemy.orm import DeclarativeBase


# ── SQLAlchemy ORM ────────────────────────────────────────────────────────────

class Base(DeclarativeBase):
    pass


class OAuthClient(Base):
    """Registered MCP clients."""
    __tablename__ = "oauth_clients"

    client_id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    client_secret_hash = Column(String, nullable=True)  # None for public clients
    client_name = Column(String, nullable=False)
    redirect_uris = Column(Text, nullable=False)          # JSON array stored as text
    scopes = Column(Text, nullable=False, default="[]")   # JSON array
    is_public = Column(Boolean, default=False)            # PKCE-only clients
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class AuthorizationCode(Base):
    """Short-lived auth codes issued during the authorization flow."""
    __tablename__ = "authorization_codes"

    code = Column(String, primary_key=True)
    client_id = Column(String, nullable=False)
    user_id = Column(String, nullable=False)
    redirect_uri = Column(String, nullable=False)
    scopes = Column(Text, nullable=False)
    code_challenge = Column(String, nullable=True)        # PKCE
    code_challenge_method = Column(String, nullable=True) # S256 or plain
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)


class AccessToken(Base):
    """Issued access tokens with MCP scope metadata."""
    __tablename__ = "access_tokens"

    token = Column(String, primary_key=True)
    client_id = Column(String, nullable=False)
    user_id = Column(String, nullable=False)
    scopes = Column(Text, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    revoked = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    # MCP-specific metadata
    mcp_server_id = Column(String, nullable=True)         # Which MCP server this is for
    tool_allowlist = Column(Text, nullable=True)          # JSON array of allowed tool names


class RefreshToken(Base):
    """Long-lived refresh tokens."""
    __tablename__ = "refresh_tokens"

    token = Column(String, primary_key=True)
    access_token = Column(String, nullable=False)
    client_id = Column(String, nullable=False)
    user_id = Column(String, nullable=False)
    scopes = Column(Text, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    revoked = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)


# ── Pydantic request/response schemas ─────────────────────────────────────────

class ClientRegistrationRequest(BaseModel):
    client_name: str
    redirect_uris: List[str]
    scopes: List[str] = []
    is_public: bool = False  # True = PKCE-only, no client secret


class ClientRegistrationResponse(BaseModel):
    client_id: str
    client_secret: Optional[str] = None  # Only returned at registration time
    client_name: str
    redirect_uris: List[str]
    scopes: List[str]
    is_public: bool


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    refresh_token: Optional[str] = None
    scope: str


class TokenIntrospectionResponse(BaseModel):
    active: bool
    client_id: Optional[str] = None
    user_id: Optional[str] = None
    scope: Optional[str] = None
    exp: Optional[int] = None
    iat: Optional[int] = None
    mcp_server_id: Optional[str] = None
    tool_allowlist: Optional[List[str]] = None


class ErrorResponse(BaseModel):
    error: str
    error_description: Optional[str] = None
