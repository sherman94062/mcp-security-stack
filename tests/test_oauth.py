import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from mcp_oauth_server.main import app
from mcp_oauth_server.storage import init_db


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    await init_db()


@pytest.mark.asyncio
async def test_health():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_discovery_metadata():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/.well-known/oauth-authorization-server")
    data = resp.json()
    assert "authorization_endpoint" in data
    assert "token_endpoint" in data
    assert "introspection_endpoint" in data
    assert "S256" in data["code_challenge_methods_supported"]


@pytest.mark.asyncio
async def test_register_confidential_client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/register", json={
            "client_name": "Zepz Payment Agent",
            "redirect_uris": ["http://localhost:3000/callback"],
            "scopes": ["mcp:payments:transfer_funds", "mcp:payments:get_balance"],
            "is_public": False,
        })
    assert resp.status_code == 201
    data = resp.json()
    assert data["client_id"]
    assert data["client_secret"]  # Returned once at registration
    assert data["is_public"] is False


@pytest.mark.asyncio
async def test_register_public_client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/register", json={
            "client_name": "Zepz Mobile App",
            "redirect_uris": ["http://localhost:3000/callback"],
            "scopes": ["openid", "profile"],
            "is_public": True,
        })
    assert resp.status_code == 201
    data = resp.json()
    assert data["client_secret"] is None  # Public clients get no secret


@pytest.mark.asyncio
async def test_client_credentials_flow():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Register M2M client
        reg = await client.post("/register", json={
            "client_name": "AML Agent",
            "redirect_uris": ["http://localhost/callback"],
            "scopes": ["mcp:compliance:check_transaction"],
            "is_public": False,
        })
        creds = reg.json()

        # Get token via client_credentials
        token_resp = await client.post("/token", data={
            "grant_type": "client_credentials",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            "scope": "mcp:compliance:check_transaction",
        })

    assert token_resp.status_code == 200
    token_data = token_resp.json()
    assert token_data["access_token"]
    assert token_data["token_type"] == "Bearer"
    assert "mcp:compliance:check_transaction" in token_data["scope"]


@pytest.mark.asyncio
async def test_token_introspection():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Register issuing client
        reg = await client.post("/register", json={
            "client_name": "FX Agent",
            "redirect_uris": ["http://localhost/callback"],
            "scopes": ["mcp:fx:get_rate"],
            "is_public": False,
        })
        creds = reg.json()

        # Get token
        token_resp = await client.post("/token", data={
            "grant_type": "client_credentials",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            "scope": "mcp:fx:get_rate",
        })
        access_token = token_resp.json()["access_token"]

        # Introspect — MCP server validates the token
        introspect_resp = await client.post("/introspect", data={
            "token": access_token,
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
        })

    data = introspect_resp.json()
    assert data["active"] is True
    assert "mcp:fx:get_rate" in data["scope"]


@pytest.mark.asyncio
async def test_revocation():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        reg = await client.post("/register", json={
            "client_name": "Revoke Test Client",
            "redirect_uris": ["http://localhost/callback"],
            "scopes": ["mcp:test:tool"],
            "is_public": False,
        })
        creds = reg.json()

        token_resp = await client.post("/token", data={
            "grant_type": "client_credentials",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            "scope": "mcp:test:tool",
        })
        access_token = token_resp.json()["access_token"]

        # Revoke it
        revoke_resp = await client.post("/revoke", data={
            "token": access_token,
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
        })
        assert revoke_resp.status_code == 200

        # Introspect — should now be inactive
        introspect_resp = await client.post("/introspect", data={
            "token": access_token,
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
        })
        assert introspect_resp.json()["active"] is False
