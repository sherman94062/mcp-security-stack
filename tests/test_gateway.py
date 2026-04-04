import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, patch
from httpx import AsyncClient, ASGITransport

from mcp_gateway.main import app
from mcp_gateway.storage import init_gateway_db
from mcp_gateway.config import gateway_settings

ADMIN_HEADERS = {"x-admin-key": gateway_settings.GATEWAY_ADMIN_KEY}

SAMPLE_SERVER = {
    "server_id":    "payments-server",
    "display_name": "Payments MCP Server",
    "base_url":     "http://payments-mcp:9000",
    "description":  "Handles payment tool calls",
    "health_url":   "http://payments-mcp:9000/health",
}

ALLOW_ALL_POLICY = {
    "client_id":     "aml-agent",
    "server_id":     "payments-server",
    "allowed_tools": ["*"],
    "effect":        "allow",
    "rate_limit_rpm": 100,
    "rate_limit_rpd": 5000,
}


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    await init_gateway_db()


@pytest.mark.asyncio
async def test_health():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/health")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_register_server():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/admin/servers", json=SAMPLE_SERVER, headers=ADMIN_HEADERS)
    assert resp.status_code == 201
    assert resp.json()["server_id"] == "payments-server"


@pytest.mark.asyncio
async def test_admin_requires_auth():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/admin/servers", json=SAMPLE_SERVER,
                                 headers={"x-admin-key": "wrong"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_create_policy():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Register server first
        await client.post("/admin/servers", json=SAMPLE_SERVER, headers=ADMIN_HEADERS)
        resp = await client.post("/admin/policies", json=ALLOW_ALL_POLICY, headers=ADMIN_HEADERS)
    assert resp.status_code == 201
    data = resp.json()
    assert data["client_id"] == "aml-agent"
    assert "*" in data["allowed_tools"]


@pytest.mark.asyncio
async def test_gateway_denied_no_token():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post("/admin/servers", json=SAMPLE_SERVER, headers=ADMIN_HEADERS)
        resp = await client.post(
            "/gateway/payments-server/tools/check_transaction",
            json={"transaction_id": "tx_001"},
        )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_gateway_denied_no_policy():
    """Token is valid but no policy exists for this client — should be denied (fail-closed)."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post("/admin/servers", json=SAMPLE_SERVER, headers=ADMIN_HEADERS)
        # No policy created for "unknown-agent"
        resp = await client.post(
            "/gateway/payments-server/tools/check_transaction",
            json={"transaction_id": "tx_001"},
            headers={"Authorization": "Bearer dev-unknown-agent-token"},
        )
    assert resp.status_code == 403
    assert "denied" in resp.json()["error"]


@pytest.mark.asyncio
async def test_gateway_tool_not_in_policy():
    """Policy exists but only allows specific tools."""
    restricted_policy = {
        "client_id":     "read-only-agent",
        "server_id":     "payments-server",
        "allowed_tools": ["get_balance"],  # NOT transfer_funds
        "effect":        "allow",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post("/admin/servers", json=SAMPLE_SERVER, headers=ADMIN_HEADERS)
        await client.post("/admin/policies", json=restricted_policy, headers=ADMIN_HEADERS)

        resp = await client.post(
            "/gateway/payments-server/tools/transfer_funds",
            json={"amount": 1000},
            headers={"Authorization": "Bearer dev-read-only-agent-token"},
        )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_gateway_explicit_deny_policy():
    """Explicit DENY policy blocks even if an ALLOW also exists."""
    deny_policy = {
        "client_id": "blocked-agent",
        "server_id": "payments-server",
        "allowed_tools": ["*"],
        "effect": "deny",
        "notes": "This agent was compromised",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post("/admin/servers", json=SAMPLE_SERVER, headers=ADMIN_HEADERS)
        await client.post("/admin/policies", json=deny_policy, headers=ADMIN_HEADERS)

        resp = await client.post(
            "/gateway/payments-server/tools/any_tool",
            json={},
            headers={"Authorization": "Bearer dev-blocked-agent-token"},
        )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_gateway_unknown_server():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/gateway/nonexistent-server/tools/some_tool",
            json={},
            headers={"Authorization": "Bearer dev-aml-agent-token"},
        )
    assert resp.status_code == 403  # Policy eval fails — no server registered


@pytest.mark.asyncio
async def test_gateway_proxies_when_allowed():
    """When policy allows, gateway should proxy to backend (mock the HTTP call)."""
    mock_response = (200, {"result": "transaction_safe", "risk_score": 0.05}, 12.3)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post("/admin/servers", json=SAMPLE_SERVER, headers=ADMIN_HEADERS)
        await client.post("/admin/policies", json=ALLOW_ALL_POLICY, headers=ADMIN_HEADERS)

        with patch("mcp_gateway.routers.gateway.forward_request", return_value=mock_response), \
             patch("mcp_gateway.routers.gateway.log_tool_call", new_callable=AsyncMock):
            resp = await client.post(
                "/gateway/payments-server/tools/check_transaction",
                json={"transaction_id": "tx_001", "amount": 500},
                headers={"Authorization": "Bearer dev-aml-agent-token"},
            )

    assert resp.status_code == 200
    assert resp.json()["result"] == "transaction_safe"
    assert "x-trace-id" in resp.headers
    assert "x-ratelimit-remaining-rpm" in resp.headers


@pytest.mark.asyncio
async def test_list_policies():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post("/admin/servers", json=SAMPLE_SERVER, headers=ADMIN_HEADERS)
        await client.post("/admin/policies", json=ALLOW_ALL_POLICY, headers=ADMIN_HEADERS)
        resp = await client.get("/admin/policies?client_id=aml-agent", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert len(resp.json()) >= 1
