from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .storage import init_secrets_db
from .config import secrets_settings
from .routers import secrets, lease, admin


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_secrets_db()
    yield


app = FastAPI(
    title="MCP Secret Management Server",
    description=(
        "Runtime secret delivery for MCP servers. "
        "MCP servers request short-lived leases for credentials — "
        "no hardcoded API keys, no secrets in environment variables. "
        "Supports local encrypted storage, HashiCorp Vault, "
        "AWS Secrets Manager, and GCP Secret Manager."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(secrets.router)
app.include_router(lease.router)
app.include_router(admin.router)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "mcp-secrets-server"}
