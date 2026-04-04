import asyncio
import json
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import FilterRequest, FilterResponse, FilterAction, RedactionStrategy
from ..storage import get_db, get_rule_for_target, log_detection
from ..redactor import redact_payload
from ..config import pii_settings

router = APIRouter(prefix="/filter", tags=["PII Filter"])


def _require_filter_key(x_pii_filter_key: str = Header(...)):
    if x_pii_filter_key != pii_settings.PII_FILTER_KEY:
        raise HTTPException(status_code=401, detail="Invalid PII filter key")


@router.post("", response_model=FilterResponse)
async def filter_payload(
    request: FilterRequest,
    db: AsyncSession = Depends(get_db),
    _auth=Depends(_require_filter_key),
):
    """
    Scan and redact PII from an MCP tool input or output payload.

    MCP servers (or the Gateway) POST payloads here before logging or
    forwarding across a trust boundary.

    The response always contains:
    - clean_payload: the redacted/masked version (safe to log/forward)
    - detections: what was found and how it was handled
    - pii_found: bool
    - blocked: True if action=BLOCK and PII was found

    Example — redact a transfer payload:
        POST /filter
        {
            "payload": {
                "sender_name": "John Smith",
                "sender_email": "john@example.com",
                "amount": 500,
                "wallet_address": "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"
            },
            "server_id": "payments-server",
            "tool_name": "transfer_funds",
            "direction": "input"
        }
    """

    # ── Load rule for this server/tool ────────────────────────────────────────
    rule = None
    if not request.override_types:
        rule = await get_rule_for_target(db, request.server_id, request.tool_name)

    # Determine effective settings
    if request.override_types:
        enabled_types = [t.value for t in request.override_types]
    elif rule and rule.enabled_types:
        enabled_types = json.loads(rule.enabled_types)
    else:
        enabled_types = pii_settings.DEFAULT_ENABLED_TYPES

    if request.override_strategy:
        strategy = request.override_strategy.value
    elif rule:
        strategy = rule.strategy
    else:
        strategy = pii_settings.DEFAULT_STRATEGY

    if request.override_action:
        action = request.override_action.value
    elif rule:
        action = rule.action
    else:
        action = FilterAction.REDACT.value

    # Field allowlist: fields whose values are never scanned
    field_allowlist = set()
    if rule and rule.field_allowlist:
        field_allowlist = set(json.loads(rule.field_allowlist))

    # Check direction filter
    if rule and rule.direction != "both" and rule.direction != request.direction:
        # Rule doesn't apply to this direction — pass through unchanged
        return FilterResponse(
            clean_payload=request.payload,
            detections=[],
            pii_found=False,
            blocked=False,
            detection_count=0,
            trace_id=request.trace_id,
        )

    # ── Run redactor ──────────────────────────────────────────────────────────
    clean_payload, detections = redact_payload(
        payload=request.payload,
        enabled_types=enabled_types,
        strategy=strategy,
        field_allowlist=field_allowlist if field_allowlist else None,
    )

    pii_found = len(detections) > 0
    blocked = pii_found and action == FilterAction.BLOCK

    # ── Log detection summary (no PII values in log) ──────────────────────────
    if pii_found:
        pii_types_found = list({d.pii_type.value for d in detections})
        asyncio.create_task(log_detection(
            db=db,
            server_id=request.server_id,
            tool_name=request.tool_name,
            client_id=request.client_id,
            direction=request.direction,
            pii_types_found=pii_types_found,
            action_taken=action,
            trace_id=request.trace_id,
        ))

    return FilterResponse(
        clean_payload=clean_payload,
        detections=detections,
        pii_found=pii_found,
        blocked=blocked,
        detection_count=len(detections),
        trace_id=request.trace_id,
    )
