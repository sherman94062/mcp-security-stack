import json
from datetime import datetime
from typing import Optional, List

from sqlalchemy import select, func, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from .models import Base, AuditEvent, AuditEventCreate, AuditQueryParams
from .config import audit_settings

engine = create_async_engine(audit_settings.DATABASE_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


async def init_audit_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session


# ── Write ─────────────────────────────────────────────────────────────────────

async def insert_event(db: AsyncSession, payload: AuditEventCreate) -> AuditEvent:
    """
    Append-only insert. Never called with update/delete on audit rows.
    Serializes JSON fields before storage.
    """
    event = AuditEvent(
        client_id=payload.client_id,
        user_id=payload.user_id,
        agent_name=payload.agent_name,
        mcp_server_id=payload.mcp_server_id,
        tool_name=payload.tool_name,
        tool_input=json.dumps(payload.tool_input) if payload.tool_input is not None else None,
        tool_output=json.dumps(payload.tool_output) if payload.tool_output is not None else None,
        outcome=payload.outcome.value,
        error_message=payload.error_message,
        duration_ms=payload.duration_ms,
        severity=payload.severity.value,
        caller_ip=payload.caller_ip,
        trace_id=payload.trace_id,
        session_id=payload.session_id,
        token_scopes=json.dumps(payload.token_scopes) if payload.token_scopes else None,
        policy_decision=payload.policy_decision,
    )
    db.add(event)
    await db.commit()
    await db.refresh(event)
    return event


# ── Read ──────────────────────────────────────────────────────────────────────

async def query_events(db: AsyncSession, params: AuditQueryParams) -> List[AuditEvent]:
    stmt = select(AuditEvent).order_by(AuditEvent.created_at.desc())

    if params.client_id:
        stmt = stmt.where(AuditEvent.client_id == params.client_id)
    if params.user_id:
        stmt = stmt.where(AuditEvent.user_id == params.user_id)
    if params.mcp_server_id:
        stmt = stmt.where(AuditEvent.mcp_server_id == params.mcp_server_id)
    if params.tool_name:
        stmt = stmt.where(AuditEvent.tool_name == params.tool_name)
    if params.outcome:
        stmt = stmt.where(AuditEvent.outcome == params.outcome.value)
    if params.severity:
        stmt = stmt.where(AuditEvent.severity == params.severity.value)
    if params.trace_id:
        stmt = stmt.where(AuditEvent.trace_id == params.trace_id)
    if params.session_id:
        stmt = stmt.where(AuditEvent.session_id == params.session_id)
    if params.from_ts:
        stmt = stmt.where(AuditEvent.created_at >= params.from_ts)
    if params.to_ts:
        stmt = stmt.where(AuditEvent.created_at <= params.to_ts)

    stmt = stmt.limit(params.limit).offset(params.offset)
    result = await db.execute(stmt)
    return result.scalars().all()


async def get_event_by_id(db: AsyncSession, event_id: str) -> Optional[AuditEvent]:
    result = await db.execute(select(AuditEvent).where(AuditEvent.event_id == event_id))
    return result.scalar_one_or_none()


async def get_summary(
    db: AsyncSession,
    from_ts: Optional[datetime] = None,
    to_ts: Optional[datetime] = None,
) -> dict:
    """Aggregate stats for compliance dashboards."""
    base = select(AuditEvent)
    if from_ts:
        base = base.where(AuditEvent.created_at >= from_ts)
    if to_ts:
        base = base.where(AuditEvent.created_at <= to_ts)

    # Total counts by outcome
    count_stmt = select(
        AuditEvent.outcome,
        func.count().label("cnt")
    ).group_by(AuditEvent.outcome)
    if from_ts:
        count_stmt = count_stmt.where(AuditEvent.created_at >= from_ts)
    if to_ts:
        count_stmt = count_stmt.where(AuditEvent.created_at <= to_ts)

    counts_result = await db.execute(count_stmt)
    counts = {row.outcome: row.cnt for row in counts_result}

    # Top tools
    top_tools_stmt = (
        select(AuditEvent.tool_name, func.count().label("cnt"))
        .group_by(AuditEvent.tool_name)
        .order_by(func.count().desc())
        .limit(10)
    )
    if from_ts:
        top_tools_stmt = top_tools_stmt.where(AuditEvent.created_at >= from_ts)
    top_tools_result = await db.execute(top_tools_stmt)
    top_tools = [{"tool": r.tool_name, "count": r.cnt} for r in top_tools_result]

    # Top clients
    top_clients_stmt = (
        select(AuditEvent.client_id, func.count().label("cnt"))
        .group_by(AuditEvent.client_id)
        .order_by(func.count().desc())
        .limit(10)
    )
    if from_ts:
        top_clients_stmt = top_clients_stmt.where(AuditEvent.created_at >= from_ts)
    top_clients_result = await db.execute(top_clients_stmt)
    top_clients = [{"client_id": r.client_id, "count": r.cnt} for r in top_clients_result]

    # Avg duration
    avg_stmt = select(func.avg(AuditEvent.duration_ms))
    if from_ts:
        avg_stmt = avg_stmt.where(AuditEvent.created_at >= from_ts)
    avg_result = await db.execute(avg_stmt)
    avg_duration = avg_result.scalar()

    total = sum(counts.values())
    return {
        "total_events":    total,
        "success_count":   counts.get("success", 0),
        "failure_count":   counts.get("failure", 0),
        "denied_count":    counts.get("denied", 0),
        "error_count":     counts.get("error", 0),
        "top_tools":       top_tools,
        "top_clients":     top_clients,
        "avg_duration_ms": round(avg_duration, 2) if avg_duration else None,
        "period_start":    from_ts,
        "period_end":      to_ts,
    }
