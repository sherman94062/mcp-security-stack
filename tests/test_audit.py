import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from mcp_audit_server.main import app
from mcp_audit_server.storage import init_audit_db
from mcp_audit_server.config import audit_settings

INGEST_HEADERS = {"x-audit-api-key": audit_settings.AUDIT_INGEST_API_KEY}
READ_HEADERS   = {"x-audit-read-key": audit_settings.AUDIT_READ_API_KEY}

SAMPLE_EVENT = {
    "client_id":     "zepz-aml-agent",
    "user_id":       "user_123",
    "agent_name":    "AML Transaction Monitor",
    "mcp_server_id": "payments-server",
    "tool_name":     "check_transaction",
    "tool_input":    {"transaction_id": "tx_abc123", "amount": 5000, "currency": "USD"},
    "tool_output":   {"risk_score": 0.12, "decision": "allow"},
    "outcome":       "success",
    "duration_ms":   42.5,
    "severity":      "info",
    "trace_id":      "trace-xyz-001",
    "session_id":    "session-001",
    "token_scopes":  ["mcp:compliance:check_transaction"],
}


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    await init_audit_db()


@pytest.mark.asyncio
async def test_health():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/health")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_ingest_event():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/events", json=SAMPLE_EVENT, headers=INGEST_HEADERS)
    assert resp.status_code == 201
    data = resp.json()
    assert "event_id" in data
    assert "created_at" in data


@pytest.mark.asyncio
async def test_ingest_requires_auth():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/events", json=SAMPLE_EVENT,
                                 headers={"x-audit-api-key": "wrong-key"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_retrieve_event():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        ingest = await client.post("/events", json=SAMPLE_EVENT, headers=INGEST_HEADERS)
        event_id = ingest.json()["event_id"]

        resp = await client.get(f"/events/{event_id}", headers=READ_HEADERS)

    assert resp.status_code == 200
    data = resp.json()
    assert data["event_id"] == event_id
    assert data["tool_name"] == "check_transaction"
    assert data["outcome"] == "success"
    assert data["tool_input"]["transaction_id"] == "tx_abc123"


@pytest.mark.asyncio
async def test_query_by_client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post("/events", json=SAMPLE_EVENT, headers=INGEST_HEADERS)

        resp = await client.get("/events",
                                params={"client_id": "zepz-aml-agent"},
                                headers=READ_HEADERS)
    assert resp.status_code == 200
    events = resp.json()
    assert len(events) >= 1
    assert all(e["client_id"] == "zepz-aml-agent" for e in events)


@pytest.mark.asyncio
async def test_query_by_outcome():
    denied_event = {**SAMPLE_EVENT, "outcome": "denied", "severity": "critical",
                    "tool_name": "transfer_funds", "policy_decision": "scope_insufficient"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post("/events", json=denied_event, headers=INGEST_HEADERS)

        resp = await client.get("/events",
                                params={"outcome": "denied"},
                                headers=READ_HEADERS)
    assert resp.status_code == 200
    events = resp.json()
    assert all(e["outcome"] == "denied" for e in events)


@pytest.mark.asyncio
async def test_summary():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post("/events", json=SAMPLE_EVENT, headers=INGEST_HEADERS)
        resp = await client.get("/export/summary", headers=READ_HEADERS)

    assert resp.status_code == 200
    data = resp.json()
    assert "total_events" in data
    assert "top_tools" in data
    assert data["total_events"] >= 1


@pytest.mark.asyncio
async def test_ndjson_export():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post("/events", json=SAMPLE_EVENT, headers=INGEST_HEADERS)
        resp = await client.get("/export/ndjson", headers=READ_HEADERS)

    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/x-ndjson"
    lines = [l for l in resp.text.strip().split("\n") if l]
    assert len(lines) >= 1
    import json
    record = json.loads(lines[0])
    assert "event_id" in record
    assert "tool_name" in record


@pytest.mark.asyncio
async def test_read_requires_auth():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/events", headers={"x-audit-read-key": "wrong"})
    assert resp.status_code == 401
