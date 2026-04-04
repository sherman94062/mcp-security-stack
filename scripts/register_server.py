#!/usr/bin/env python3
"""
MCP Security Stack — Server Registration Script

Deploys a new MCP server into the security stack by reading a YAML config
and making the required API calls across all five servers.

Usage:
    python scripts/register_server.py scripts/servers/payments-server.yaml

    # With custom stack URLs (e.g. remote environment):
    MCP_OAUTH_URL=https://oauth.example.com \\
    MCP_AUDIT_URL=https://audit.example.com \\
    MCP_GATEWAY_URL=https://gateway.example.com \\
    MCP_SECRETS_URL=https://secrets.example.com \\
    MCP_PII_URL=https://pii.example.com \\
    python scripts/register_server.py scripts/servers/payments-server.yaml

What this script does:
    1. Register the MCP server with the Gateway
    2. Store all secrets in the Secrets Server (encrypted)
    3. Register OAuth clients for each agent
    4. Create Gateway access policies (which agent → which tools)
    5. Create Secrets access policies (which agent → which secrets)
    6. Create PII filter rules for this server's tools
    7. Print a deployment summary with all generated credentials
"""

import os
import sys
import json
import yaml
import httpx
import argparse
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


# ── Stack URLs (override via env vars) ────────────────────────────────────────

OAUTH_URL   = os.getenv("MCP_OAUTH_URL",   "http://localhost:8080")
AUDIT_URL   = os.getenv("MCP_AUDIT_URL",   "http://localhost:8081")
GATEWAY_URL = os.getenv("MCP_GATEWAY_URL", "http://localhost:8082")
SECRETS_URL = os.getenv("MCP_SECRETS_URL", "http://localhost:8083")
PII_URL     = os.getenv("MCP_PII_URL",     "http://localhost:8084")

# ── Admin keys (override via env vars or read from .env) ──────────────────────

GATEWAY_ADMIN_KEY = os.getenv("GATEWAY_ADMIN_KEY", "dev-admin-key-change-in-production")
SECRETS_ADMIN_KEY = os.getenv("SECRETS_ADMIN_KEY", "dev-secrets-admin-change-in-production")
PII_ADMIN_KEY     = os.getenv("PII_ADMIN_KEY",     "dev-pii-admin-change-in-production")


# ── Colours for terminal output ───────────────────────────────────────────────

GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def ok(msg):    print(f"  {GREEN}✓{RESET} {msg}")
def warn(msg):  print(f"  {YELLOW}⚠{RESET} {msg}")
def err(msg):   print(f"  {RED}✗{RESET} {msg}")
def info(msg):  print(f"  {CYAN}→{RESET} {msg}")
def header(msg): print(f"\n{BOLD}{msg}{RESET}")


# ── HTTP helpers ───────────────────────────────────────────────────────────────

def post(url: str, payload: dict, headers: dict) -> dict:
    try:
        resp = httpx.post(url, json=payload, headers=headers, timeout=10)
        if resp.status_code in (200, 201):
            return resp.json()
        err(f"POST {url} → {resp.status_code}: {resp.text[:200]}")
        return {}
    except Exception as e:
        err(f"POST {url} failed: {e}")
        return {}


def check_health(name: str, url: str) -> bool:
    try:
        resp = httpx.get(f"{url}/health", timeout=5)
        if resp.status_code == 200:
            ok(f"{name} is reachable at {url}")
            return True
    except Exception:
        pass
    err(f"{name} is NOT reachable at {url}")
    return False


# ── Registration steps ─────────────────────────────────────────────────────────

def register_server_with_gateway(server: dict) -> bool:
    header("Step 1 — Register server with Gateway")
    info(f"Registering '{server['id']}' → {server['base_url']}")
    result = post(
        f"{GATEWAY_URL}/admin/servers",
        {
            "server_id":    server["id"],
            "display_name": server["display_name"],
            "base_url":     server["base_url"],
            "health_url":   server.get("health_url"),
            "description":  server.get("description"),
        },
        {"x-admin-key": GATEWAY_ADMIN_KEY, "Content-Type": "application/json"},
    )
    if result.get("server_id"):
        ok(f"Server registered: {result['server_id']}")
        return True
    return False


def store_secrets(secrets: list) -> dict:
    """Returns map of secret_name → secret_id."""
    header("Step 2 — Store secrets in Secrets Server")
    secret_ids = {}

    for secret in secrets:
        name      = secret["name"]
        value_env = secret.get("value_env")

        # Read value from environment variable
        value = os.getenv(value_env, "") if value_env else ""
        if not value:
            warn(f"Secret '{name}': env var {value_env} is not set — skipping")
            warn(f"  Set it with: export {value_env}=your-actual-key")
            continue

        info(f"Storing '{name}' ({secret['backend']} backend)")
        result = post(
            f"{SECRETS_URL}/secrets",
            {
                "name":        name,
                "description": secret.get("description", ""),
                "backend":     secret.get("backend", "local"),
                "backend_path": secret.get("backend_path", name),
                "value":       value,
                "tags":        secret.get("tags", ""),
            },
            {"x-admin-key": SECRETS_ADMIN_KEY, "Content-Type": "application/json"},
        )
        if result.get("secret_id"):
            secret_ids[name] = result["secret_id"]
            ok(f"Stored: {name} (id: {result['secret_id'][:8]}...)")
        else:
            err(f"Failed to store secret: {name}")

    return secret_ids


def register_agents(
    agents: list, server_id: str
) -> dict:
    """Returns map of agent_id → {client_id, client_secret}."""
    header("Step 3 — Register OAuth clients for agents")
    credentials = {}

    for agent in agents:
        agent_id = agent["id"]
        info(f"Registering agent: {agent['name']}")

        result = post(
            f"{OAUTH_URL}/register",
            {
                "client_name":   agent["name"],
                "redirect_uris": [f"http://localhost/{agent_id}/callback"],
                "scopes": [
                    f"mcp:{server_id}:{tool}"
                    for tool in agent.get("allowed_tools", [])
                ],
                "is_public": agent.get("is_public", False),
            },
            {"Content-Type": "application/json"},
        )
        if result.get("client_id"):
            credentials[agent_id] = {
                "client_id":     result["client_id"],
                "client_secret": result.get("client_secret"),
            }
            ok(f"Registered: {agent_id} → client_id: {result['client_id'][:16]}...")
        else:
            err(f"Failed to register OAuth client for {agent_id}")

    return credentials


def create_gateway_policies(agents: list, server_id: str, agent_credentials: dict):
    header("Step 4 — Create Gateway access policies")

    for agent in agents:
        agent_id  = agent["id"]
        client_id = agent_credentials.get(agent_id, {}).get("client_id", agent_id)

        info(f"Policy: {agent_id} → {server_id} [{', '.join(agent.get('allowed_tools', ['*']))}]")
        result = post(
            f"{GATEWAY_URL}/admin/policies",
            {
                "client_id":      client_id,
                "server_id":      server_id,
                "allowed_tools":  agent.get("allowed_tools", ["*"]),
                "effect":         "allow",
                "rate_limit_rpm": agent.get("rate_limit_rpm"),
                "rate_limit_rpd": agent.get("rate_limit_rpd"),
                "notes":          agent.get("notes", ""),
            },
            {"x-admin-key": GATEWAY_ADMIN_KEY, "Content-Type": "application/json"},
        )
        if result.get("policy_id"):
            ok(f"Created policy: {result['policy_id'][:16]}...")
        else:
            err(f"Failed to create gateway policy for {agent_id}")


def create_secrets_policies(agents: list, agent_credentials: dict):
    header("Step 5 — Create Secrets access policies")

    for agent in agents:
        agent_id  = agent["id"]
        client_id = agent_credentials.get(agent_id, {}).get("client_id", agent_id)
        patterns  = agent.get("secret_patterns", [])

        if not patterns:
            info(f"No secret patterns for {agent_id} — skipping")
            continue

        for pattern in patterns:
            info(f"Secret policy: {agent_id} → {pattern} (max TTL: {agent.get('max_lease_ttl', 300)}s)")
            result = post(
                f"{SECRETS_URL}/admin/policies",
                {
                    "client_id":      client_id,
                    "secret_pattern": pattern,
                    "max_lease_ttl":  agent.get("max_lease_ttl", 300),
                    "notes":          agent.get("notes", ""),
                },
                {"x-admin-key": SECRETS_ADMIN_KEY, "Content-Type": "application/json"},
            )
            if result.get("policy_id"):
                ok(f"Created secret policy: {result['policy_id'][:16]}...")
            else:
                err(f"Failed to create secret policy: {agent_id} → {pattern}")


def create_pii_rules(pii_rules: list):
    header("Step 6 — Create PII filter rules")

    for rule in pii_rules:
        target = rule["target"]
        info(f"PII rule: {target} ({rule.get('direction', 'both')}) → {rule.get('strategy', 'REDACT')}/{rule.get('action', 'REDACT')}")
        result = post(
            f"{PII_URL}/rules",
            {
                "target":          target,
                "direction":       rule.get("direction", "both"),
                "enabled_types":   rule.get("enabled_types"),
                "strategy":        rule.get("strategy", "REDACT"),
                "action":          rule.get("action", "REDACT"),
                "field_allowlist": rule.get("field_allowlist"),
                "notes":           rule.get("notes", ""),
            },
            {"x-pii-admin-key": PII_ADMIN_KEY, "Content-Type": "application/json"},
        )
        if result.get("rule_id"):
            ok(f"Created PII rule: {result['rule_id'][:16]}...")
        else:
            err(f"Failed to create PII rule for {target}")


def print_summary(server: dict, agents: list, agent_credentials: dict):
    header("═" * 60)
    print(f"{BOLD}Deployment Summary — {server['id']}{RESET}")
    header("═" * 60)

    print(f"\n{BOLD}Server{RESET}")
    print(f"  ID:      {server['id']}")
    print(f"  URL:     {server['base_url']}")
    print(f"  Gateway: {GATEWAY_URL}/gateway/{server['id']}/tools/{{tool_name}}")

    print(f"\n{BOLD}Agent Credentials{RESET}")
    print(f"  {'Agent':<25} {'Client ID':<38} {'Client Secret'}")
    print(f"  {'-'*25} {'-'*38} {'-'*20}")
    for agent in agents:
        agent_id = agent["id"]
        creds    = agent_credentials.get(agent_id, {})
        cid      = creds.get("client_id", "FAILED")[:36]
        secret   = creds.get("client_secret", "N/A (public client)")
        secret_display = secret[:20] + "..." if secret and len(secret) > 20 else (secret or "N/A")
        print(f"  {agent_id:<25} {cid:<38} {secret_display}")

    print(f"\n{BOLD}Next steps for your MCP server{RESET}")
    print(f"""
  1. Add the audit middleware (auto-logs every tool call):

       from mcp_audit_server.middleware import MCPAuditMiddleware
       app.add_middleware(
           MCPAuditMiddleware,
           audit_server_url="{AUDIT_URL}",
           audit_api_key="<AUDIT_INGEST_API_KEY>",
           mcp_server_id="{server['id']}",
       )

  2. Add the PII filter middleware (auto-redacts I/O):

       from mcp_pii_filter.middleware import PIIFilterMiddleware
       app.add_middleware(
           PIIFilterMiddleware,
           filter_server_url="{PII_URL}",
           filter_api_key="<PII_FILTER_KEY>",
           server_id="{server['id']}",
       )

  3. Fetch secrets at runtime via lease (never hardcode):

       import httpx
       resp = httpx.post(
           "{SECRETS_URL}/leases",
           json={{"secret_name": "payments/stripe-api-key", "purpose": "processing payment"}},
           headers={{
               "x-secrets-key": "<SECRETS_INGEST_KEY>",
               "x-mcp-client-id": "<your-agent-client-id>",
           }}
       )
       stripe_key = resp.json()["secret_value"]
       # Key expires in resp.json()["ttl_seconds"] seconds

  4. Agents call tools through the Gateway (not directly):

       POST {GATEWAY_URL}/gateway/{server['id']}/tools/{{tool_name}}
       Authorization: Bearer <access_token>
""")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Register a new MCP server with the MCP Security Stack"
    )
    parser.add_argument("config", help="Path to server YAML config file")
    parser.add_argument("--dry-run", action="store_true",
                        help="Validate config and check connectivity without making changes")
    args = parser.parse_args()

    config_path = Path(args.config)
    if not config_path.exists():
        print(f"{RED}Config file not found: {config_path}{RESET}")
        sys.exit(1)

    with open(config_path) as f:
        config = yaml.safe_load(f)

    server    = config["server"]
    secrets   = config.get("secrets", [])
    agents    = config.get("agents", [])
    pii_rules = config.get("pii_rules", [])

    print(f"\n{BOLD}MCP Security Stack — Server Registration{RESET}")
    print(f"Config: {config_path}")
    print(f"Server: {server['id']} ({server['display_name']})")

    # ── Health checks ─────────────────────────────────────────────
    header("Checking stack connectivity")
    all_healthy = all([
        check_health("OAuth Server",   OAUTH_URL),
        check_health("Audit Server",   AUDIT_URL),
        check_health("Gateway",        GATEWAY_URL),
        check_health("Secrets Server", SECRETS_URL),
        check_health("PII Filter",     PII_URL),
    ])

    if not all_healthy:
        print(f"\n{YELLOW}Some servers are not reachable. Start the stack first:{RESET}")
        print("  make up   # Docker")
        print("  make dev-oauth dev-audit dev-gateway dev-secrets dev-pii  # Local")
        if not args.dry_run:
            sys.exit(1)

    if args.dry_run:
        ok("Dry run complete — config is valid")
        sys.exit(0)

    # ── Execute registration ──────────────────────────────────────
    register_server_with_gateway(server)
    store_secrets(secrets)
    agent_credentials = register_agents(agents, server["id"])
    create_gateway_policies(agents, server["id"], agent_credentials)
    create_secrets_policies(agents, agent_credentials)
    create_pii_rules(pii_rules)
    print_summary(server, agents, agent_credentials)

    print(f"\n{GREEN}{BOLD}Registration complete.{RESET}\n")


if __name__ == "__main__":
    main()
