import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from mcp_secrets_server.main import app
from mcp_secrets_server.storage import init_secrets_db
from mcp_secrets_server.config import secrets_settings

ADMIN_HEADERS  = {"x-admin-key": secrets_settings.SECRETS_ADMIN_KEY}
INGEST_HEADERS = {"x-secrets-key": secrets_settings.SECRETS_INGEST_KEY}

LOCAL_SECRET = {
    "name":        "stripe-api-key",
    "description": "Stripe live API key for payment processing",
    "backend":     "local",
    "value":       "sk_live_super_secret_stripe_key_abc123",
    "tags":        "payments,stripe,prod",
    "created_by":  "admin",
}

PAYMENTS_SECRET = {
    "name":    "payments/trmm-api-key",
    "backend": "local",
    "value":   "trm-secret-key-xyz789",
    "tags":    "payments,compliance",
}


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    await init_secrets_db()


@pytest.mark.asyncio
async def test_health():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/health")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_register_local_secret():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/secrets", json=LOCAL_SECRET, headers=ADMIN_HEADERS)
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "stripe-api-key"
    assert "value" not in data            # Value must never appear in response
    assert "encrypted_value" not in data  # Nor the ciphertext


@pytest.mark.asyncio
async def test_secret_requires_admin():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/secrets", json=LOCAL_SECRET,
                                 headers={"x-admin-key": "wrong"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_list_secrets_no_values():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post("/secrets", json=LOCAL_SECRET, headers=ADMIN_HEADERS)
        resp = await client.get("/secrets", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    for secret in resp.json():
        assert "value" not in secret
        assert "encrypted_value" not in secret


@pytest.mark.asyncio
async def test_create_access_policy():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/admin/policies", json={
            "client_id":      "aml-agent",
            "secret_pattern": "payments/*",
            "max_lease_ttl":  300,
            "notes":          "AML agent needs TRM and Fireblocks keys",
        }, headers=ADMIN_HEADERS)
    assert resp.status_code == 201
    assert resp.json()["secret_pattern"] == "payments/*"


@pytest.mark.asyncio
async def test_lease_denied_no_policy():
    """Client with no matching policy cannot get a lease."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post("/secrets", json=LOCAL_SECRET, headers=ADMIN_HEADERS)
        resp = await client.post("/leases", json={
            "secret_name": "stripe-api-key",
            "purpose":     "test",
        }, headers={**INGEST_HEADERS, "x-mcp-client-id": "unauthorized-agent"})
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_lease_issued_with_policy():
    """With a matching policy, client receives the secret value in the lease."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Register secret
        await client.post("/secrets", json=LOCAL_SECRET, headers=ADMIN_HEADERS)
        # Grant access
        await client.post("/admin/policies", json={
            "client_id":      "payments-agent",
            "secret_pattern": "stripe-api-key",
            "max_lease_ttl":  600,
        }, headers=ADMIN_HEADERS)
        # Request lease
        resp = await client.post("/leases", json={
            "secret_name": "stripe-api-key",
            "ttl_seconds": 300,
            "purpose":     "Processing refund for order #12345",
        }, headers={**INGEST_HEADERS, "x-mcp-client-id": "payments-agent"})

    assert resp.status_code == 201
    data = resp.json()
    assert data["secret_value"] == "sk_live_super_secret_stripe_key_abc123"
    assert data["ttl_seconds"] == 300
    assert "lease_id" in data
    assert "expires_at" in data


@pytest.mark.asyncio
async def test_lease_ttl_capped_by_policy():
    """Requested TTL is capped at the policy max."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post("/secrets", json=LOCAL_SECRET, headers=ADMIN_HEADERS)
        await client.post("/admin/policies", json={
            "client_id":      "restricted-agent",
            "secret_pattern": "stripe-api-key",
            "max_lease_ttl":  60,   # Policy caps at 60 seconds
        }, headers=ADMIN_HEADERS)
        resp = await client.post("/leases", json={
            "secret_name": "stripe-api-key",
            "ttl_seconds": 3600,   # Requesting 1 hour
        }, headers={**INGEST_HEADERS, "x-mcp-client-id": "restricted-agent"})

    assert resp.status_code == 201
    assert resp.json()["ttl_seconds"] == 60   # Capped at policy max


@pytest.mark.asyncio
async def test_wildcard_policy():
    """Wildcard pattern 'payments/*' covers all secrets under that prefix."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post("/secrets", json=PAYMENTS_SECRET, headers=ADMIN_HEADERS)
        await client.post("/admin/policies", json={
            "client_id":      "compliance-agent",
            "secret_pattern": "payments/*",
        }, headers=ADMIN_HEADERS)
        resp = await client.post("/leases", json={
            "secret_name": "payments/trmm-api-key",
        }, headers={**INGEST_HEADERS, "x-mcp-client-id": "compliance-agent"})

    assert resp.status_code == 201
    assert resp.json()["secret_value"] == "trm-secret-key-xyz789"


@pytest.mark.asyncio
async def test_lease_revocation():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post("/secrets", json=LOCAL_SECRET, headers=ADMIN_HEADERS)
        await client.post("/admin/policies", json={
            "client_id": "revoke-test-agent",
            "secret_pattern": "stripe-api-key",
        }, headers=ADMIN_HEADERS)
        lease_resp = await client.post("/leases", json={
            "secret_name": "stripe-api-key",
        }, headers={**INGEST_HEADERS, "x-mcp-client-id": "revoke-test-agent"})
        lease_id = lease_resp.json()["lease_id"]

        revoke_resp = await client.delete(f"/leases/{lease_id}", headers=ADMIN_HEADERS)
        assert revoke_resp.status_code == 204

        # Verify lease shows as revoked
        leases = await client.get(
            "/leases?active_only=false",
            headers=ADMIN_HEADERS,
        )
        revoked = [l for l in leases.json() if l["lease_id"] == lease_id]
        assert revoked[0]["status"] == "revoked"


@pytest.mark.asyncio
async def test_rotation():
    """After rotation, next lease returns new value."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        reg = await client.post("/secrets", json=LOCAL_SECRET, headers=ADMIN_HEADERS)
        secret_id = reg.json()["secret_id"]
        await client.post("/admin/policies", json={
            "client_id": "rotation-test-agent",
            "secret_pattern": "stripe-api-key",
        }, headers=ADMIN_HEADERS)

        # Rotate to new value
        await client.post(f"/secrets/{secret_id}/rotate",
                          json={"new_value": "sk_live_NEW_rotated_key_xyz"},
                          headers=ADMIN_HEADERS)

        # New lease should return new value
        resp = await client.post("/leases", json={"secret_name": "stripe-api-key"},
                                 headers={**INGEST_HEADERS, "x-mcp-client-id": "rotation-test-agent"})
        assert resp.json()["secret_value"] == "sk_live_NEW_rotated_key_xyz"


@pytest.mark.asyncio
async def test_backend_health():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/admin/backends/health", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert resp.json()["backends"]["local"]["healthy"] is True
