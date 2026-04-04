"""
Policy evaluation engine.

Evaluation order:
1. Is the target server registered and active?
2. Is there an explicit DENY policy for this client+server+tool? → 403
3. Is there an explicit ALLOW policy covering this tool? → check rate limit
4. No matching policy → deny by default (fail-closed)
5. Rate limit check against both RPM and RPD windows
"""

import json
import logging
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from .models import PolicyDecision, PolicyEffect
from .storage import (
    get_server,
    get_policies_for_client,
    increment_and_get_count,
    get_current_count,
)
from .config import gateway_settings

logger = logging.getLogger("mcp_gateway.policy")


async def evaluate(
    db: AsyncSession,
    client_id: str,
    server_id: str,
    tool_name: str,
) -> PolicyDecision:
    """
    Evaluate whether client_id is allowed to call tool_name on server_id.
    Returns a PolicyDecision with allowed=True/False and a human-readable reason.
    """

    # ── 1. Server must exist and be active ────────────────────────────────────
    server = await get_server(db, server_id)
    if not server or not server.is_active:
        return PolicyDecision(
            allowed=False,
            reason=f"Unknown or inactive MCP server: {server_id}",
        )

    # ── 2. Load applicable policies ───────────────────────────────────────────
    policies = await get_policies_for_client(db, client_id, server_id)

    if not policies:
        return PolicyDecision(
            allowed=False,
            reason="No policy found for this client+server — denied by default (fail-closed)",
        )

    # ── 3. Check each policy in priority order ────────────────────────────────
    matching_allow_policy = None

    for policy in policies:
        allowed_tools = json.loads(policy.allowed_tools)
        tool_match = "*" in allowed_tools or tool_name in allowed_tools

        if not tool_match:
            continue

        if policy.effect == PolicyEffect.DENY.value:
            logger.warning(
                "DENY policy %s triggered: client=%s server=%s tool=%s",
                policy.policy_id, client_id, server_id, tool_name
            )
            return PolicyDecision(
                allowed=False,
                reason=f"Explicit DENY policy {policy.policy_id}",
                policy_id=policy.policy_id,
            )

        if policy.effect == PolicyEffect.ALLOW.value and matching_allow_policy is None:
            matching_allow_policy = policy

    if not matching_allow_policy:
        return PolicyDecision(
            allowed=False,
            reason=f"Tool '{tool_name}' not in any ALLOW policy for this client+server",
        )

    # ── 4. Rate limit check ───────────────────────────────────────────────────
    rpm_limit = matching_allow_policy.rate_limit_rpm or gateway_settings.DEFAULT_RATE_LIMIT_RPM
    rpd_limit = matching_allow_policy.rate_limit_rpd or gateway_settings.DEFAULT_RATE_LIMIT_RPD

    # Get current counts before incrementing (for remaining calculation)
    current_rpm = await get_current_count(db, client_id, server_id, "minute")
    current_rpd = await get_current_count(db, client_id, server_id, "day")

    if current_rpm >= rpm_limit:
        return PolicyDecision(
            allowed=False,
            reason=f"Rate limit exceeded: {rpm_limit} requests/minute",
            policy_id=matching_allow_policy.policy_id,
            rate_limited=True,
            remaining_rpm=0,
            remaining_rpd=max(0, rpd_limit - current_rpd),
        )

    if current_rpd >= rpd_limit:
        return PolicyDecision(
            allowed=False,
            reason=f"Rate limit exceeded: {rpd_limit} requests/day",
            policy_id=matching_allow_policy.policy_id,
            rate_limited=True,
            remaining_rpm=max(0, rpm_limit - current_rpm),
            remaining_rpd=0,
        )

    # ── 5. Increment counters ─────────────────────────────────────────────────
    new_rpm = await increment_and_get_count(db, client_id, server_id, "minute")
    new_rpd = await increment_and_get_count(db, client_id, server_id, "day")

    return PolicyDecision(
        allowed=True,
        reason=f"Allowed by policy {matching_allow_policy.policy_id}",
        policy_id=matching_allow_policy.policy_id,
        rate_limited=False,
        remaining_rpm=max(0, rpm_limit - new_rpm),
        remaining_rpd=max(0, rpd_limit - new_rpd),
    )
