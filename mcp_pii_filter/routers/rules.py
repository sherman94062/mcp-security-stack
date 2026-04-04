import json
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import FilterRuleCreate, FilterRuleResponse, PIISummary
from ..storage import get_db, create_rule, list_rules, deactivate_rule, get_pii_summary
from ..config import pii_settings

router = APIRouter(prefix="/rules", tags=["Filter Rules"])


def _require_admin(x_pii_admin_key: str = Header(...)):
    if x_pii_admin_key != pii_settings.PII_ADMIN_KEY:
        raise HTTPException(status_code=401, detail="Invalid PII admin key")


def _serialize_rule(rule) -> FilterRuleResponse:
    return FilterRuleResponse(
        rule_id=rule.rule_id,
        target=rule.target,
        direction=rule.direction,
        enabled_types=json.loads(rule.enabled_types) if rule.enabled_types else None,
        strategy=rule.strategy,
        action=rule.action,
        field_allowlist=json.loads(rule.field_allowlist) if rule.field_allowlist else None,
        is_active=rule.is_active,
        created_at=rule.created_at,
        notes=rule.notes,
    )


@router.post("", response_model=FilterRuleResponse, status_code=201)
async def add_rule(
    data: FilterRuleCreate,
    db: AsyncSession = Depends(get_db),
    _auth=Depends(_require_admin),
):
    """
    Create a PII filter rule for a server, server/tool pair, or wildcard.

    Examples:

    Redact all PII on all MCP servers (global default):
        { "target": "*", "strategy": "REDACT", "action": "REDACT" }

    Mask (not fully redact) for the compliance server output:
        { "target": "compliance-server", "direction": "output",
          "strategy": "MASK", "action": "REDACT" }

    Block any input to transfer_funds that contains credit card numbers:
        { "target": "payments-server/transfer_funds", "direction": "input",
          "enabled_types": ["CREDIT_CARD", "SSN"],
          "strategy": "REDACT", "action": "BLOCK" }

    Allow wallet addresses to pass through on the blockchain tool
    (field allowlist — those fields won't be scanned):
        { "target": "blockchain-server/get_wallet_balance",
          "field_allowlist": ["wallet_address", "from_address", "to_address"] }
    """
    rule = await create_rule(db, data)
    return _serialize_rule(rule)


@router.get("", response_model=List[FilterRuleResponse])
async def get_rules(
    db: AsyncSession = Depends(get_db),
    _auth=Depends(_require_admin),
):
    rules = await list_rules(db)
    return [_serialize_rule(r) for r in rules]


@router.delete("/{rule_id}", status_code=204)
async def delete_rule(
    rule_id: str,
    db: AsyncSession = Depends(get_db),
    _auth=Depends(_require_admin),
):
    await deactivate_rule(db, rule_id)


@router.get("/summary", response_model=PIISummary)
async def pii_summary(
    from_ts: Optional[datetime] = Query(default=None),
    to_ts:   Optional[datetime] = Query(default=None),
    db: AsyncSession = Depends(get_db),
    _auth=Depends(_require_admin),
):
    """
    Aggregate PII detection stats.
    Answer questions like: which tools are leaking the most PII?
    Which PII type is most common? Use for GDPR/compliance reporting.
    """
    data = await get_pii_summary(db, from_ts=from_ts, to_ts=to_ts)
    return PIISummary(**data)
