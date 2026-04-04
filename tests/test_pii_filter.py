import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from mcp_pii_filter.main import app
from mcp_pii_filter.storage import init_pii_db
from mcp_pii_filter.config import pii_settings
from mcp_pii_filter.detectors import scan_text
from mcp_pii_filter.detectors.regex_detector import CreditCardDetector
from mcp_pii_filter.redactor import redact_payload

FILTER_HEADERS = {"x-pii-filter-key": pii_settings.PII_FILTER_KEY}
ADMIN_HEADERS  = {"x-pii-admin-key":  pii_settings.PII_ADMIN_KEY}

ALL_TYPES = pii_settings.DEFAULT_ENABLED_TYPES


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    await init_pii_db()


# ── Unit tests for detectors ──────────────────────────────────────────────────

def test_email_detection():
    hits = scan_text("Contact john.smith@example.com for support", ["EMAIL"])
    assert any(v == "john.smith@example.com" for v, t in hits)


def test_credit_card_luhn_valid():
    det = CreditCardDetector()
    # Valid Visa test number
    hits = det.scan("Card: 4111 1111 1111 1111")
    assert len(hits) == 1
    assert hits[0][1] == "CREDIT_CARD"


def test_credit_card_luhn_invalid():
    det = CreditCardDetector()
    hits = det.scan("Number: 4111 1111 1111 1112")  # Fails Luhn
    assert len(hits) == 0


def test_ssn_detection():
    hits = scan_text("SSN: 123-45-6789", ["SSN"])
    assert any("123-45-6789" in v for v, t in hits)


def test_iban_detection():
    hits = scan_text("IBAN: GB82WEST12345698765432", ["IBAN"])
    assert len(hits) >= 1


def test_bitcoin_detection():
    hits = scan_text("Send to: 1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf1Na", ["CRYPTO_BTC"])
    assert len(hits) >= 1
    assert hits[0][1] == "CRYPTO_BTC"


def test_ethereum_detection():
    hits = scan_text("ETH wallet: 0x742d35Cc6634C0532925a3b844Bc454e4438f44e", ["CRYPTO_ETH"])
    assert len(hits) == 1
    assert hits[0][1] == "CRYPTO_ETH"


def test_solana_detection():
    text = "solana wallet: 9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"
    hits = scan_text(text, ["CRYPTO_SOL"])
    assert len(hits) >= 1
    assert hits[0][1] == "CRYPTO_SOL"


def test_phone_detection():
    hits = scan_text("Call +1-555-867-5309 for help", ["PHONE"])
    assert len(hits) >= 1


def test_ip_address_detection():
    hits = scan_text("Request from 203.0.113.42", ["IP_ADDRESS"])
    assert len(hits) >= 1
    # Private IPs should NOT be flagged
    private_hits = scan_text("Server at 192.168.1.1", ["IP_ADDRESS"])
    assert len(private_hits) == 0


# ── Unit tests for redactor ───────────────────────────────────────────────────

def test_redact_strategy():
    payload = {"email": "jane@example.com", "amount": 500}
    clean, detections = redact_payload(payload, ["EMAIL"], "REDACT")
    assert clean["email"] == "[REDACTED:EMAIL]"
    assert clean["amount"] == 500
    assert len(detections) == 1


def test_mask_strategy_email():
    payload = {"contact": "jane@example.com"}
    clean, detections = redact_payload(payload, ["EMAIL"], "MASK")
    assert "@example.com" in clean["contact"]
    assert "jane" not in clean["contact"]


def test_mask_strategy_credit_card():
    payload = {"card": "4111 1111 1111 1111"}
    clean, detections = redact_payload(payload, ["CREDIT_CARD"], "MASK")
    assert "1111" in clean["card"]
    assert clean["card"].startswith("****")


def test_hash_strategy():
    payload = {"email": "jane@example.com"}
    clean1, _ = redact_payload(payload, ["EMAIL"], "HASH")
    clean2, _ = redact_payload(payload, ["EMAIL"], "HASH")
    # Same input → same hash (deterministic)
    assert clean1["email"] == clean2["email"]
    assert clean1["email"].startswith("[HASH:")


def test_flag_strategy_preserves_value():
    payload = {"email": "jane@example.com"}
    clean, detections = redact_payload(payload, ["EMAIL"], "FLAG")
    assert clean["email"] == "jane@example.com"  # Value unchanged
    assert detections[0].original == "jane@example.com"


def test_field_allowlist():
    payload = {"wallet_address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e", "name": "Jane"}
    clean, detections = redact_payload(
        payload, ["CRYPTO_ETH", "PERSON_NAME"], "REDACT",
        field_allowlist={"wallet_address"}  # Wallet field is exempt
    )
    # wallet_address should pass through unchanged
    assert clean["wallet_address"] == "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"


def test_nested_payload_redaction():
    payload = {
        "sender": {"name": "John Smith", "email": "john@example.com"},
        "amount": 1000,
        "notes": "Call me at +1-555-867-5309",
    }
    clean, detections = redact_payload(payload, ALL_TYPES, "REDACT")
    assert "[REDACTED:EMAIL]" in clean["sender"]["email"]
    assert "[REDACTED:PHONE]" in clean["notes"]
    assert clean["amount"] == 1000


# ── Integration tests via HTTP API ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_health():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/health")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_filter_api_redacts_pii():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/filter", json={
            "payload": {
                "sender_name":  "John Smith",
                "sender_email": "john@example.com",
                "card_number":  "4111 1111 1111 1111",
                "amount":       500,
            },
            "server_id": "payments-server",
            "tool_name": "transfer_funds",
            "direction": "input",
        }, headers=FILTER_HEADERS)

    assert resp.status_code == 200
    data = resp.json()
    assert data["pii_found"] is True
    assert "[REDACTED:EMAIL]" in data["clean_payload"]["sender_email"]
    assert "[REDACTED:CREDIT_CARD]" in data["clean_payload"]["card_number"]
    assert data["clean_payload"]["amount"] == 500  # Numbers pass through


@pytest.mark.asyncio
async def test_filter_api_no_pii():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/filter", json={
            "payload": {"transaction_id": "tx_abc123", "amount": 250, "currency": "USD"},
            "direction": "input",
        }, headers=FILTER_HEADERS)

    assert resp.status_code == 200
    data = resp.json()
    assert data["pii_found"] is False
    assert data["blocked"] is False
    assert data["clean_payload"]["transaction_id"] == "tx_abc123"


@pytest.mark.asyncio
async def test_block_action_via_rule():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Create a BLOCK rule for this tool
        await client.post("/rules", json={
            "target":         "payments-server/high-value-transfer",
            "direction":      "input",
            "enabled_types":  ["CREDIT_CARD", "SSN"],
            "strategy":       "REDACT",
            "action":         "BLOCK",
        }, headers=ADMIN_HEADERS)

        resp = await client.post("/filter", json={
            "payload":    {"card": "4111 1111 1111 1111"},
            "server_id":  "payments-server",
            "tool_name":  "high-value-transfer",
            "direction":  "input",
        }, headers=FILTER_HEADERS)

    assert resp.status_code == 200
    data = resp.json()
    assert data["blocked"] is True


@pytest.mark.asyncio
async def test_field_allowlist_via_rule():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post("/rules", json={
            "target":          "blockchain-server/get_wallet_balance",
            "field_allowlist": ["wallet_address"],
        }, headers=ADMIN_HEADERS)

        eth_addr = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
        resp = await client.post("/filter", json={
            "payload":   {"wallet_address": eth_addr, "email": "test@example.com"},
            "server_id": "blockchain-server",
            "tool_name": "get_wallet_balance",
            "direction": "input",
        }, headers=FILTER_HEADERS)

    data = resp.json()
    assert data["clean_payload"]["wallet_address"] == eth_addr  # Allowlisted
    assert "[REDACTED:EMAIL]" in data["clean_payload"]["email"]   # Still redacted


@pytest.mark.asyncio
async def test_pii_summary():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Generate some detections
        await client.post("/filter", json={
            "payload": {"email": "user@test.com"}, "direction": "input"
        }, headers=FILTER_HEADERS)

        resp = await client.get("/rules/summary", headers=ADMIN_HEADERS)

    assert resp.status_code == 200
    data = resp.json()
    assert "total_scans" in data
    assert "by_type" in data


@pytest.mark.asyncio
async def test_filter_requires_auth():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/filter", json={
            "payload": {"email": "test@test.com"}, "direction": "input"
        }, headers={"x-pii-filter-key": "wrong"})
    assert resp.status_code == 401
