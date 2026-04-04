from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .storage import init_pii_db
from .config import pii_settings
from .routers import filter, rules


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_pii_db()
    yield


app = FastAPI(
    title="MCP PII Filter",
    description=(
        "PII detection and redaction for MCP tool payloads. "
        "Scans tool inputs and outputs for 15 PII types including emails, "
        "phone numbers, credit cards, SSNs, IBANs, bank accounts, "
        "Bitcoin/Ethereum/Solana wallet addresses, IP addresses, "
        "passport numbers, national IDs, and person names. "
        "Supports REDACT, MASK, HASH, and FLAG strategies with "
        "per-server/per-tool configurable rules and BLOCK action."
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

app.include_router(filter.router)
app.include_router(rules.router)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "mcp-pii-filter"}
