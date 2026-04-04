import json
from datetime import datetime
from typing import Optional, List, Dict

from sqlalchemy import select, update, func
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from .models import Base, FilterRule, PIIDetectionLog
from .config import pii_settings

engine = create_async_engine(pii_settings.DATABASE_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


async def init_pii_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session


# ── Filter rules ──────────────────────────────────────────────────────────────

async def create_rule(db: AsyncSession, data) -> FilterRule:
    rule = FilterRule(
        target=data.target,
        direction=data.direction,
        enabled_types=json.dumps([t.value for t in data.enabled_types]) if data.enabled_types else None,
        strategy=data.strategy.value,
        action=data.action.value,
        field_allowlist=json.dumps(data.field_allowlist) if data.field_allowlist else None,
        notes=data.notes,
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return rule


async def get_rule_for_target(
    db: AsyncSession, server_id: Optional[str], tool_name: Optional[str]
) -> Optional[FilterRule]:
    """
    Find the most specific matching rule.
    Priority: server/tool > server > *
    """
    candidates = []

    if server_id and tool_name:
        specific = f"{server_id}/{tool_name}"
        r = await db.execute(
            select(FilterRule).where(FilterRule.target == specific, FilterRule.is_active == True)
        )
        rule = r.scalar_one_or_none()
        if rule:
            return rule

    if server_id:
        r = await db.execute(
            select(FilterRule).where(FilterRule.target == server_id, FilterRule.is_active == True)
        )
        rule = r.scalar_one_or_none()
        if rule:
            return rule

    # Wildcard fallback
    r = await db.execute(
        select(FilterRule).where(FilterRule.target == "*", FilterRule.is_active == True)
    )
    return r.scalar_one_or_none()


async def list_rules(db: AsyncSession) -> List[FilterRule]:
    result = await db.execute(select(FilterRule).where(FilterRule.is_active == True))
    return result.scalars().all()


async def deactivate_rule(db: AsyncSession, rule_id: str):
    await db.execute(
        update(FilterRule).where(FilterRule.rule_id == rule_id).values(is_active=False)
    )
    await db.commit()


# ── Detection logging ─────────────────────────────────────────────────────────

async def log_detection(
    db: AsyncSession,
    server_id: Optional[str],
    tool_name: Optional[str],
    client_id: Optional[str],
    direction: str,
    pii_types_found: List[str],
    action_taken: str,
    trace_id: Optional[str] = None,
):
    log = PIIDetectionLog(
        server_id=server_id,
        tool_name=tool_name,
        client_id=client_id,
        direction=direction,
        pii_types_found=json.dumps(pii_types_found),
        detection_count=len(pii_types_found),
        action_taken=action_taken,
        trace_id=trace_id,
    )
    db.add(log)
    await db.commit()


async def get_pii_summary(
    db: AsyncSession,
    from_ts: Optional[datetime] = None,
    to_ts: Optional[datetime] = None,
) -> dict:
    stmt = select(PIIDetectionLog)
    if from_ts:
        stmt = stmt.where(PIIDetectionLog.detected_at >= from_ts)
    if to_ts:
        stmt = stmt.where(PIIDetectionLog.detected_at <= to_ts)

    result = await db.execute(stmt)
    logs = result.scalars().all()

    by_type: Dict[str, int] = {}
    by_server: Dict[str, int] = {}
    by_tool: Dict[str, int] = {}
    total_detections = 0

    for log in logs:
        types = json.loads(log.pii_types_found)
        total_detections += log.detection_count
        for t in types:
            by_type[t] = by_type.get(t, 0) + 1
        if log.server_id:
            by_server[log.server_id] = by_server.get(log.server_id, 0) + 1
        if log.tool_name:
            by_tool[log.tool_name] = by_tool.get(log.tool_name, 0) + 1

    return {
        "total_scans":      len(logs),
        "total_detections": total_detections,
        "by_type":          by_type,
        "by_server":        by_server,
        "by_tool":          by_tool,
        "period_start":     from_ts,
        "period_end":       to_ts,
    }
