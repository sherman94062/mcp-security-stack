.PHONY: help up down build test logs ps clean keygen

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# ── Docker Compose ────────────────────────────────────────────────────────────

up: ## Start all five servers (detached)
	docker compose up --build -d

down: ## Stop all servers
	docker compose down

build: ## Build images without starting
	docker compose build

logs: ## Tail logs from all servers
	docker compose logs -f

ps: ## Show running container status
	docker compose ps

restart: ## Restart all servers
	docker compose restart

# ── Local dev (without Docker) ────────────────────────────────────────────────

install: ## Install Python dependencies
	pip install -r requirements.txt

test: ## Run all test suites
	pytest tests/ -v

test-oauth: ## Run only OAuth tests
	pytest tests/test_oauth.py -v

test-audit: ## Run only audit tests
	pytest tests/test_audit.py -v

test-gateway: ## Run only gateway tests
	pytest tests/test_gateway.py -v

test-secrets: ## Run only secrets tests
	pytest tests/test_secrets.py -v

test-pii: ## Run only PII filter tests
	pytest tests/test_pii_filter.py -v

dev-oauth: ## Start OAuth server locally
	uvicorn mcp_oauth_server.main:app --port 8080 --reload

dev-audit: ## Start Audit server locally
	uvicorn mcp_audit_server.main:app --port 8081 --reload

dev-gateway: ## Start Gateway locally
	uvicorn mcp_gateway.main:app --port 8082 --reload

dev-secrets: ## Start Secrets server locally
	uvicorn mcp_secrets_server.main:app --port 8083 --reload

dev-pii: ## Start PII Filter locally
	uvicorn mcp_pii_filter.main:app --port 8084 --reload

# ── Health checks ─────────────────────────────────────────────────────────────

health: ## Check health of all five servers
	@echo "Checking all servers..."
	@curl -sf http://localhost:8080/health | python3 -c "import sys,json; d=json.load(sys.stdin); print('  ✓ OAuth   :8080 -', d['status'])" || echo "  ✗ OAuth   :8080 - DOWN"
	@curl -sf http://localhost:8081/health | python3 -c "import sys,json; d=json.load(sys.stdin); print('  ✓ Audit   :8081 -', d['status'])" || echo "  ✗ Audit   :8081 - DOWN"
	@curl -sf http://localhost:8082/health | python3 -c "import sys,json; d=json.load(sys.stdin); print('  ✓ Gateway :8082 -', d['status'])" || echo "  ✗ Gateway :8082 - DOWN"
	@curl -sf http://localhost:8083/health | python3 -c "import sys,json; d=json.load(sys.stdin); print('  ✓ Secrets :8083 -', d['status'])" || echo "  ✗ Secrets :8083 - DOWN"
	@curl -sf http://localhost:8084/health | python3 -c "import sys,json; d=json.load(sys.stdin); print('  ✓ PII     :8084 -', d['status'])" || echo "  ✗ PII     :8084 - DOWN"

# ── Key generation ────────────────────────────────────────────────────────────

keygen: ## Generate all required keys and print a ready-to-use .env block
	@python3 -c "\
import secrets; \
from cryptography.fernet import Fernet; \
print('# Paste into your .env file'); \
print('SECRET_KEY=' + secrets.token_urlsafe(32)); \
print('AUDIT_INGEST_API_KEY=' + secrets.token_urlsafe(32)); \
print('AUDIT_READ_API_KEY=' + secrets.token_urlsafe(32)); \
print('GATEWAY_ADMIN_KEY=' + secrets.token_urlsafe(32)); \
print('SECRETS_ADMIN_KEY=' + secrets.token_urlsafe(32)); \
print('SECRETS_INGEST_KEY=' + secrets.token_urlsafe(32)); \
print('MASTER_ENCRYPTION_KEY=' + Fernet.generate_key().decode()); \
print('PII_ADMIN_KEY=' + secrets.token_urlsafe(32)); \
print('PII_FILTER_KEY=' + secrets.token_urlsafe(32)); \
"

# ── Cleanup ───────────────────────────────────────────────────────────────────

register: ## Register a new MCP server: make register SERVER=scripts/servers/payments-server.yaml
	@if [ -z "$(SERVER)" ]; then echo "Usage: make register SERVER=scripts/servers/your-server.yaml"; exit 1; fi
	python scripts/register_server.py $(SERVER)

register-dry-run: ## Validate config + check connectivity: make register-dry-run SERVER=...
	@if [ -z "$(SERVER)" ]; then echo "Usage: make register-dry-run SERVER=scripts/servers/your-server.yaml"; exit 1; fi
	python scripts/register_server.py $(SERVER) --dry-run

clean: ## Remove containers, volumes, and local .db files
	docker compose down -v
	find . -name "*.db" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete
