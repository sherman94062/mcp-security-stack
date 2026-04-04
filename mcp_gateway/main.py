from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .storage import init_gateway_db
from .config import gateway_settings
from .routers import gateway, admin


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_gateway_db()
    yield


app = FastAPI(
    title="MCP Gateway",
    description=(
        "Policy-enforcing reverse proxy for MCP tool calls. "
        "Validates OAuth tokens, evaluates per-client access policies, "
        "enforces rate limits, proxies to backend MCP servers, "
        "and logs every call to the MCP Audit Server. "
        "Single chokepoint for all agent-to-tool traffic."
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

app.include_router(gateway.router)
app.include_router(admin.router)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "mcp-gateway"}


@app.get("/")
async def root():
    return {
        "service": "MCP Gateway",
        "version": "0.1.0",
        "endpoints": {
            "tool_calls": "POST /gateway/{server_id}/tools/{tool_name}",
            "admin":      "/admin/*",
            "health":     "/health",
        },
    }
