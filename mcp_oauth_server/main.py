from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .storage import init_db
from .config import settings
from .routers import register, authorize, token, introspect, revoke


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title="MCP OAuth Server",
    description=(
        "Production-ready OAuth 2.0 Authorization Server purpose-built for "
        "MCP (Model Context Protocol) deployments. Supports PKCE, token introspection, "
        "dynamic client registration, and MCP-scoped tool allowlists."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Tighten in production
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(register.router)
app.include_router(authorize.router)
app.include_router(token.router)
app.include_router(introspect.router)
app.include_router(revoke.router)


# ── OAuth Discovery Endpoint (RFC 8414) ───────────────────────────────────────
@app.get("/.well-known/oauth-authorization-server")
async def oauth_metadata():
    """
    OAuth 2.0 Authorization Server Metadata.
    MCP clients discover endpoints here automatically.
    """
    base = settings.BASE_URL
    return {
        "issuer": base,
        "authorization_endpoint": f"{base}/authorize",
        "token_endpoint": f"{base}/token",
        "introspection_endpoint": f"{base}/introspect",
        "revocation_endpoint": f"{base}/revoke",
        "registration_endpoint": f"{base}/register",
        "response_types_supported": ["code"],
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            "client_credentials",
        ],
        "code_challenge_methods_supported": ["S256", "plain"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_post",
            "none",  # For public/PKCE clients
        ],
        "scopes_supported": [
            "openid",
            "profile",
            "offline_access",
            "mcp:*:*",  # MCP tool scopes
        ],
    }


@app.get("/health")
async def health():
    return {"status": "ok", "service": "mcp-oauth-server"}
