import json
import asyncio
from typing import List, Optional
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Header, Query
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import AuditEventCreate, AuditEventResponse, AuditQueryParams
from ..storage import get_db, insert_event, query_events, get_event_by_id
from ..webhook import forward_to_siem
from ..config import audit_settings

router = APIRouter(prefix="/events", tags=["Audit Events"])


def _require_ingest_key(x_audit_api_key: str = Header(...)):
    if x_audit_api_key != audit_settings.AUDIT_INGEST_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid audit ingest key")


def _require_read_key(x_audit_read_key: str = Header(...)):
    if x_audit_read_key != audit_settings.AUDIT_READ_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid audit read key")


def _deserialize(event) -> AuditEventResponse:
    """Convert ORM row to response model, parsing JSON fields."""
    d = {c.name: getattr(event, c.name) for c in event.__table__.columns}
    for field in ("tool_input", "tool_output"):
        if d[field]:
            try:
                d[field] = json.loads(d[field])
            except Exception:
                pass
    if d.get("token_scopes"):
        try:
            d["token_scopes"] = json.loads(d["token_scopes"])
        except Exception:
            pass
    return AuditEventResponse(**d)


# ── Ingest ────────────────────────────────────────────────────────────────────

@router.post("", status_code=201)
async def ingest_event(
    payload: AuditEventCreate,
    db: AsyncSession = Depends(get_db),
    _auth = Depends(_require_ingest_key),
):
    """
    MCP servers POST here after every tool call.
    Returns the event_id for correlation.
    Also fires async SIEM webhook if configured.
    """
    event = await insert_event(db, payload)
    # Forward to SIEM without blocking the response
    asyncio.create_task(forward_to_siem(event))
    return {"event_id": event.event_id, "created_at": event.created_at.isoformat()}


# ── Retrieve single event ─────────────────────────────────────────────────────

@router.get("/{event_id}", response_model=AuditEventResponse)
async def get_event(
    event_id: str,
    db: AsyncSession = Depends(get_db),
    _auth = Depends(_require_read_key),
):
    event = await get_event_by_id(db, event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return _deserialize(event)


# ── Query events ──────────────────────────────────────────────────────────────

@router.get("", response_model=List[AuditEventResponse])
async def list_events(
    client_id:     Optional[str]      = Query(default=None),
    user_id:       Optional[str]      = Query(default=None),
    mcp_server_id: Optional[str]      = Query(default=None),
    tool_name:     Optional[str]      = Query(default=None),
    outcome:       Optional[str]      = Query(default=None),
    severity:      Optional[str]      = Query(default=None),
    trace_id:      Optional[str]      = Query(default=None),
    session_id:    Optional[str]      = Query(default=None),
    from_ts:       Optional[datetime] = Query(default=None),
    to_ts:         Optional[datetime] = Query(default=None),
    limit:         int                = Query(default=100, le=1000),
    offset:        int                = Query(default=0),
    db: AsyncSession = Depends(get_db),
    _auth = Depends(_require_read_key),
):
    """
    Query audit events. Supports filtering by any combination of:
    client, user, server, tool, outcome, severity, trace, session, and time range.
    """
    from ..models import EventOutcome, EventSeverity

    params = AuditQueryParams(
        client_id=client_id,
        user_id=user_id,
        mcp_server_id=mcp_server_id,
        tool_name=tool_name,
        outcome=EventOutcome(outcome) if outcome else None,
        severity=EventSeverity(severity) if severity else None,
        trace_id=trace_id,
        session_id=session_id,
        from_ts=from_ts,
        to_ts=to_ts,
        limit=limit,
        offset=offset,
    )
    events = await query_events(db, params)
    return [_deserialize(e) for e in events]
