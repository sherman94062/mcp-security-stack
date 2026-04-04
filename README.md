# MCP Security Stack

Production-grade security infrastructure for MCP (Model Context Protocol) deployments.
Five composable servers that solve the hardest operational problems in running AI agents at scale:
authentication, audit logging, policy enforcement, credential management, and PII protection.

Built with companies like **Zepz/WorldRemit/Sendwave** in mind — global regulated fintechs
running agents across 130+ countries, stablecoin rails, and strict compliance requirements.

---

## The Problem

MCP servers are being deployed into production with hardcoded API keys, no access control,
no audit trails, and tool outputs being logged verbatim alongside customer PII. This stack
fixes all of that.

---

## Architecture

```
                          ┌─────────────────────────────────────┐
                          │           AI Agent / LLM            │
                          │  (AML Monitor, FX Agent, Support)   │
                          └──────────────────┬──────────────────┘
                                             │  Bearer Token
                                             │  POST /gateway/{server}/{tool}
                                             ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                         MCP Gateway  :8082                                   │
│                                                                              │
│  1. Introspect token → OAuth Server                                          │
│  2. Evaluate policy  → ALLOW / DENY / RATE-LIMIT                            │
│  3. Proxy request    → Backend MCP Server                                    │
│  4. Log call         → Audit Server (fire-and-forget)                        │
└──────────┬──────────────────────────────┬───────────────────────────────────┘
           │                              │
           ▼                              ▼
┌─────────────────────┐        ┌──────────────────────┐
│  MCP OAuth Server   │        │  MCP Audit Server    │
│       :8080         │        │       :8081          │
│                     │        │                      │
│  Token issuance     │        │  Append-only log     │
│  PKCE enforcement   │        │  NDJSON export       │
│  Client registry    │        │  SIEM webhook        │
│  Token revocation   │        │  Compliance summary  │
└─────────────────────┘        └──────────────────────┘

           ┌─────────────────────────────────────────┐
           │          Backend MCP Servers            │
           │                                         │
           │  ┌─────────────────────────────────┐   │
           │  │  Your MCP Server (any tool)     │   │
           │  │                                 │   │
           │  │  Requests secrets at runtime ──►│──►│──► MCP Secrets Server :8083
           │  │                                 │   │      Vault / AWS / GCP / Local
           │  │  Filters I/O before logging  ──►│──►│──► MCP PII Filter :8084
           │  │                                 │   │      15 PII types, 4 strategies
           │  └─────────────────────────────────┘   │
           └─────────────────────────────────────────┘
```

---

## The Five Servers

| Port | Server | Purpose |
|------|--------|---------|
| 8080 | **OAuth Server** | Token issuance, PKCE, dynamic client registration, revocation |
| 8081 | **Audit Server** | Immutable append-only tool call log, SIEM export, compliance dashboard |
| 8082 | **Gateway** | Policy enforcement, rate limiting, token validation, proxy routing |
| 8083 | **Secrets Server** | Runtime credential delivery via short-lived leases (Vault/AWS/GCP/Local) |
| 8084 | **PII Filter** | 15-type PII detection with REDACT/MASK/HASH/BLOCK strategies |

---

## Quick Start

### 1. Clone and install

```bash
git clone https://github.com/sherman94062/mcp-security-stack.git
cd mcp-security-stack
pip install -r requirements.txt
```

### 2. Configure

```bash
cp .env.example .env
# Edit .env — at minimum set your SECRET_KEY and API keys
```

### 3. Run tests

```bash
pytest tests/ -v
```

### 4. Start all five servers

```bash
# Each in its own terminal tab
uvicorn mcp_oauth_server.main:app   --port 8080 --reload
uvicorn mcp_audit_server.main:app   --port 8081 --reload
uvicorn mcp_gateway.main:app        --port 8082 --reload
uvicorn mcp_secrets_server.main:app --port 8083 --reload
uvicorn mcp_pii_filter.main:app     --port 8084 --reload
```

### 5. Verify

```bash
curl http://localhost:8080/health  # {"status":"ok","service":"mcp-oauth-server"}
curl http://localhost:8081/health  # {"status":"ok","service":"mcp-audit-server"}
curl http://localhost:8082/health  # {"status":"ok","service":"mcp-gateway"}
curl http://localhost:8083/health  # {"status":"ok","service":"mcp-secrets-server"}
curl http://localhost:8084/health  # {"status":"ok","service":"mcp-pii-filter"}
```

---

## End-to-End Example: Zepz AML Transaction Monitor

This walkthrough shows all five servers working together for a real-world scenario:
an AML agent checking a cross-border payment on Zepz's payments MCP server.

### Step 1 — Register the AML agent as an OAuth client

```bash
curl -s -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name":   "AML Transaction Monitor",
    "redirect_uris": ["http://localhost:3000/callback"],
    "scopes":        ["mcp:payments:check_transaction", "mcp:compliance:flag_transaction"],
    "is_public":     false
  }' | jq .
```

```json
{
  "client_id":     "a3f2c1d4-...",
  "client_secret": "vK9mN2pQ...",   ← Save this — returned only once
  "client_name":   "AML Transaction Monitor",
  "scopes":        ["mcp:payments:check_transaction", "mcp:compliance:flag_transaction"],
  "is_public":     false
}
```

### Step 2 — Issue an access token (client credentials — M2M flow)

```bash
curl -s -X POST http://localhost:8080/token \
  -d "grant_type=client_credentials" \
  -d "client_id=a3f2c1d4-..." \
  -d "client_secret=vK9mN2pQ..." \
  -d "scope=mcp:payments:check_transaction" | jq .
```

```json
{
  "access_token": "FpQr7sT2uV...",
  "token_type":   "Bearer",
  "expires_in":   3600,
  "scope":        "mcp:payments:check_transaction"
}
```

### Step 3 — Register the payments MCP server with the Gateway

```bash
curl -s -X POST http://localhost:8082/admin/servers \
  -H "x-admin-key: dev-admin-key-change-in-production" \
  -H "Content-Type: application/json" \
  -d '{
    "server_id":    "payments-server",
    "display_name": "Zepz Payments MCP Server",
    "base_url":     "http://payments-mcp:9000",
    "health_url":   "http://payments-mcp:9000/health"
  }' | jq .
```

### Step 4 — Create a policy allowing the AML agent to call check_transaction

```bash
curl -s -X POST http://localhost:8082/admin/policies \
  -H "x-admin-key: dev-admin-key-change-in-production" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id":      "a3f2c1d4-...",
    "server_id":      "payments-server",
    "allowed_tools":  ["check_transaction", "get_risk_score"],
    "effect":         "allow",
    "rate_limit_rpm": 30,
    "rate_limit_rpd": 5000,
    "notes":          "AML monitor — read-only compliance tools only"
  }' | jq .
```

### Step 5 — Store the TRM Labs API key in the Secrets Server

```bash
curl -s -X POST http://localhost:8083/secrets \
  -H "x-admin-key: dev-secrets-admin-change-in-production" \
  -H "Content-Type: application/json" \
  -d '{
    "name":        "payments/trm-api-key",
    "description": "TRM Labs blockchain intelligence API key",
    "backend":     "local",
    "value":       "trm-live-key-abc123xyz",
    "tags":        "payments,compliance,trm"
  }' | jq .

# Grant the AML agent access to all payments/* secrets
curl -s -X POST http://localhost:8083/admin/policies \
  -H "x-admin-key: dev-secrets-admin-change-in-production" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id":      "aml-agent",
    "secret_pattern": "payments/*",
    "max_lease_ttl":  300
  }' | jq .
```

### Step 6 — Configure PII filtering for the payments server

```bash
# Redact PII from tool outputs — sender names, wallet addresses, emails
curl -s -X POST http://localhost:8084/rules \
  -H "x-pii-admin-key: dev-pii-admin-change-in-production" \
  -H "Content-Type: application/json" \
  -d '{
    "target":          "payments-server",
    "direction":       "output",
    "strategy":        "MASK",
    "action":          "REDACT",
    "field_allowlist": ["transaction_id", "risk_score", "decision"],
    "notes":           "Mask PII in compliance outputs; preserve transaction metadata"
  }' | jq .
```

### Step 7 — AML agent calls the Gateway to check a transaction

```bash
curl -s -X POST http://localhost:8082/gateway/payments-server/tools/check_transaction \
  -H "Authorization: Bearer FpQr7sT2uV..." \
  -H "x-trace-id: trace-zepz-20260403-001" \
  -H "x-mcp-session-id: session-aml-monitor-42" \
  -H "Content-Type: application/json" \
  -d '{
    "transaction_id": "tx_abc123",
    "amount":         5000,
    "currency":       "USDC",
    "sender_wallet":  "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin",
    "recipient_wallet": "7dHbWXmci3dT8UFYWYZweBLXgycu7Y3iL6trKn1Y7ARj",
    "corridor":       "US-KE"
  }' | jq .
```

**What happens inside the Gateway on this call:**

```
1. Extract Bearer token from Authorization header
2. POST /introspect → OAuth Server
   → token active, client_id = "a3f2c1d4-...", scopes = ["mcp:payments:check_transaction"]
3. Evaluate policy for client_id + "payments-server" + "check_transaction"
   → ALLOW, remaining_rpm: 29, remaining_rpd: 4999
4. Forward POST to http://payments-mcp:9000/tools/check_transaction
5. Payments MCP server internally:
   a. GET lease from Secrets Server for "payments/trm-api-key" (TTL 300s)
   b. Call TRM Labs API with the leased key
   c. Return risk assessment
6. POST /filter → PII Filter (output direction)
   → Mask sender/recipient names if present in response
7. POST /events → Audit Server (fire-and-forget)
   → Logged: client, tool, outcome, duration, trace_id, session_id
8. Return response to agent with headers:
   x-trace-id: trace-zepz-20260403-001
   x-ratelimit-remaining-rpm: 29
   x-ratelimit-remaining-rpd: 4999
```

**Response:**

```json
{
  "transaction_id": "tx_abc123",
  "risk_score":     0.12,
  "decision":       "allow",
  "flags":          [],
  "checked_at":     "2026-04-03T22:30:00Z"
}
```

### Step 8 — Query the audit trail for compliance review

```bash
# All calls for this trace
curl -s "http://localhost:8081/events?trace_id=trace-zepz-20260403-001" \
  -H "x-audit-read-key: dev-read-key-change-in-production" | jq .

# All denied calls in the last hour (GDPR/AML incident investigation)
curl -s "http://localhost:8081/events?outcome=denied&from_ts=2026-04-03T21:00:00" \
  -H "x-audit-read-key: dev-read-key-change-in-production" | jq .

# Export everything as NDJSON for Splunk
curl -s "http://localhost:8081/export/ndjson" \
  -H "x-audit-read-key: dev-read-key-change-in-production" \
  > audit_export.ndjson

# Compliance dashboard summary
curl -s "http://localhost:8081/export/summary" \
  -H "x-audit-read-key: dev-read-key-change-in-production" | jq .
```

### Step 9 — Emergency: lock out a compromised agent instantly

```bash
# Add an explicit DENY policy — takes effect on next request, no restarts needed
curl -s -X POST http://localhost:8082/admin/policies \
  -H "x-admin-key: dev-admin-key-change-in-production" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id":  "a3f2c1d4-...",
    "server_id":  "*",
    "allowed_tools": ["*"],
    "effect":     "deny",
    "notes":      "Agent compromised 2026-04-03 22:45 UTC — locked by security team"
  }' | jq .

# Revoke the token immediately
curl -s -X POST http://localhost:8080/revoke \
  -d "token=FpQr7sT2uV..." \
  -d "client_id=a3f2c1d4-..." \
  -d "client_secret=vK9mN2pQ..."
```

---

## Drop-in Middleware

Both the Audit Server and PII Filter ship with ASGI middleware you can add to any
existing FastAPI MCP server in three lines:

```python
from mcp_audit_server.middleware import MCPAuditMiddleware
from mcp_pii_filter.middleware import PIIFilterMiddleware

app = FastAPI()

# Auto-log every tool call to the audit server
app.add_middleware(
    MCPAuditMiddleware,
    audit_server_url="http://localhost:8081",
    audit_api_key="your-ingest-key",
    mcp_server_id="payments-server",
)

# Auto-filter PII from every tool input and output
app.add_middleware(
    PIIFilterMiddleware,
    filter_server_url="http://localhost:8084",
    filter_api_key="your-filter-key",
    server_id="payments-server",
)
```

---

## PII Types Detected

| Type | Examples |
|------|---------|
| `EMAIL` | john@example.com |
| `PHONE` | +1-555-867-5309, +44 20 7946 0958 |
| `CREDIT_CARD` | 4111 1111 1111 1111 (Luhn-validated) |
| `SSN` | 123-45-6789 |
| `IBAN` | GB82WEST12345698765432 |
| `BANK_ACCOUNT` | routing: 021000021, account: 12345678 |
| `CRYPTO_BTC` | 1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf1Na, bc1q... |
| `CRYPTO_ETH` | 0x742d35Cc6634C0532925a3b844Bc454e4438f44e |
| `CRYPTO_SOL` | 9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin |
| `IP_ADDRESS` | 203.0.113.42 (public only, skips RFC1918) |
| `DATE_OF_BIRTH` | dob: 1985-03-15 |
| `PASSPORT` | AB1234567 |
| `NATIONAL_ID` | NIN: AB123456C |
| `PERSON_NAME` | John Smith (field-context aware) |
| `URL_WITH_PII` | https://api.example.com?email=john@... |

### Redaction strategies

| Strategy | Email example | Card example |
|----------|--------------|-------------|
| `REDACT` | `[REDACTED:EMAIL]` | `[REDACTED:CREDIT_CARD]` |
| `MASK` | `j***@example.com` | `****-****-****-1111` |
| `HASH` | `[HASH:a3f2c19d8b4e]` | `[HASH:7c4e2f1a9d3b]` |
| `FLAG` | `john@example.com` + detection metadata | unchanged + metadata |

---

## Secret Backends

| Backend | Use case | Config |
|---------|---------|--------|
| `local` | Dev/test — AES-128-CBC encrypted SQLite | `MASTER_ENCRYPTION_KEY` |
| `vault` | Production — HashiCorp Vault KV v2 | `VAULT_ADDR`, `VAULT_TOKEN` |
| `aws` | Production — AWS Secrets Manager | `AWS_REGION`, IAM role |
| `gcp` | Production — GCP Secret Manager | `GCP_PROJECT_ID`, Workload Identity |

Switch backends per-secret — run local for dev, Vault for prod, without changing agent code.

---

## Key Design Principles

**Fail-closed.** The Gateway denies by default — no matching policy means no access.
The PII middleware can be configured to fail-closed (block if filter server is down).

**Append-only audit log.** No UPDATE or DELETE paths exist on audit rows anywhere
in the codebase. A log you can modify is not a log.

**Secrets never at rest in plaintext.** Local backend uses Fernet (AES-128-CBC + HMAC).
External backends (Vault/AWS/GCP) never store values here at all.

**Secret values returned exactly once.** The lease endpoint is the only place a secret
value appears. It never appears in list responses, audit logs, or error messages.

**Emergency lockout without restarts.** Add a DENY policy in the Gateway and revoke the
token in OAuth — the compromised agent is locked out on its next request, no deployments needed.

**MCP-scoped tokens.** OAuth scopes follow `mcp:{server_id}:{tool_name}` format,
so tokens are scoped to specific tools, not just broad API access.

---

## Project Structure

```
mcp-security-stack/
├── mcp_oauth_server/         # :8080 — Token issuance and validation
│   ├── main.py
│   ├── models.py             # ORM + Pydantic schemas
│   ├── storage.py            # Async SQLAlchemy
│   ├── oauth.py              # PKCE, scope utilities
│   └── routers/
│       ├── authorize.py      # GET  /authorize
│       ├── token.py          # POST /token
│       ├── introspect.py     # POST /introspect
│       ├── revoke.py         # POST /revoke
│       └── register.py       # POST /register
│
├── mcp_audit_server/         # :8081 — Immutable audit log
│   ├── main.py
│   ├── models.py
│   ├── storage.py
│   ├── webhook.py            # Async SIEM forwarding
│   ├── middleware.py         # Drop-in MCPAuditMiddleware
│   └── routers/
│       ├── events.py         # POST/GET /events
│       └── export.py         # GET /export/ndjson, /export/summary
│
├── mcp_gateway/              # :8082 — Policy enforcement + proxy
│   ├── main.py
│   ├── models.py
│   ├── storage.py
│   ├── policy.py             # ALLOW/DENY evaluation engine
│   ├── auth.py               # Token introspection client
│   ├── proxy.py              # HTTP proxy to backends
│   ├── audit_client.py       # Posts to audit server
│   └── routers/
│       ├── gateway.py        # POST /gateway/{server}/{tool}
│       └── admin.py          # Server registry + policy management
│
├── mcp_secrets_server/       # :8083 — Runtime credential delivery
│   ├── main.py
│   ├── models.py
│   ├── storage.py
│   ├── crypto.py             # Fernet encryption at rest
│   ├── audit_client.py
│   ├── backends/
│   │   ├── local.py          # Encrypted SQLite
│   │   ├── vault.py          # HashiCorp Vault KV v2
│   │   ├── aws.py            # AWS Secrets Manager
│   │   └── gcp.py            # GCP Secret Manager
│   └── routers/
│       ├── secrets.py        # Secret definition CRUD
│       ├── lease.py          # POST /leases — the core MCP interface
│       └── admin.py          # Access policies + backend health
│
├── mcp_pii_filter/           # :8084 — PII detection and redaction
│   ├── main.py
│   ├── models.py
│   ├── storage.py
│   ├── redactor.py           # REDACT/MASK/HASH/FLAG strategies
│   ├── middleware.py         # Drop-in PIIFilterMiddleware
│   ├── detectors/
│   │   ├── regex_detector.py # Email, phone, SSN, cards, IBAN, IP, DOB...
│   │   ├── crypto_detector.py# BTC, ETH, SOL wallet addresses
│   │   └── name_detector.py  # Person names (field-context heuristics)
│   └── routers/
│       ├── filter.py         # POST /filter
│       └── rules.py          # Rule management + /rules/summary
│
├── tests/
│   ├── test_oauth.py         # OAuth flows, PKCE, token lifecycle
│   ├── test_audit.py         # Ingest, query, export, NDJSON
│   ├── test_gateway.py       # Policy eval, rate limits, proxy
│   ├── test_secrets.py       # Leases, rotation, TTL caps, wildcards
│   └── test_pii_filter.py    # Detectors, strategies, rules, blocking
│
├── requirements.txt
├── .env.example
└── docker-compose.yml
```

---

## Relevance to Agent Governance

This stack is the **capability layer** that makes agent governance possible.
You cannot govern what you cannot observe, authenticate, or control.

- **OAuth Server** → every agent has a verified identity
- **Audit Server** → every action is recorded immutably
- **Gateway** → every tool call is policy-evaluated before execution
- **Secrets Server** → credentials are never embedded in agent code
- **PII Filter** → sensitive data never crosses boundaries unredacted

This maps directly to the SENESCHAL governance model in
[Castellan](https://github.com/castellan-ai) — the Gateway + Audit Server
are the enforcement and observability backbone of any agent governance platform.
