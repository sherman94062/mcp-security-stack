from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .storage import init_audit_db
from .config import audit_settings
from .routers import events, export


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_audit_db()
    yield


app = FastAPI(
    title="MCP Audit Server",
    description=(
        "Immutable append-only audit log for MCP tool calls. "
        "Captures every tool invocation with client, user, outcome, duration, "
        "and policy context. Exports to SIEM via NDJSON streaming or real-time webhook."
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

app.include_router(events.router)
app.include_router(export.router)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "mcp-audit-server"}
