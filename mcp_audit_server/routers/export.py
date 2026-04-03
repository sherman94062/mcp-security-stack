import json
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query, HTTPException, Header
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from ..storage import get_db, query_events, get_summary
from ..models import AuditQueryParams, AuditSummary
from ..config import audit_settings

router = APIRouter(prefix="/export", tags=["Export & Summary"])


def _require_read_key(x_audit_read_key: str = Header(...)):
    if x_audit_read_key != audit_settings.AUDIT_READ_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid audit read key")


# ── NDJSON streaming export (Splunk / Datadog / Elastic ingestion) ────────────

@router.get("/ndjson")
async def export_ndjson(
    from_ts:       Optional[datetime] = Query(default=None),
    to_ts:         Optional[datetime] = Query(default=None),
    mcp_server_id: Optional[str]      = Query(default=None),
    outcome:       Optional[str]      = Query(default=None),
    limit:         int                = Query(default=10000, le=50000),
    db: AsyncSession = Depends(get_db),
    _auth = Depends(_require_read_key),
):
    """
    Stream audit events as newline-delimited JSON.
    Pipe directly into Splunk HEC, Datadog Log API, or Elastic Bulk API.

    Example:
        curl -H "x-audit-read-key: ..." \
             "http://localhost:8081/export/ndjson?from_ts=2026-01-01" \
             | splunk-ingest
    """
    from ..models import EventOutcome

    params = AuditQueryParams(
        from_ts=from_ts,
        to_ts=to_ts,
        mcp_server_id=mcp_server_id,
        outcome=EventOutcome(outcome) if outcome else None,
        limit=limit,
    )
    events = await query_events(db, params)

    def generate():
        for event in events:
            record = {
                "event_id":       event.event_id,
                "created_at":     event.created_at.isoformat(),
                "client_id":      event.client_id,
                "user_id":        event.user_id,
                "agent_name":     event.agent_name,
                "mcp_server_id":  event.mcp_server_id,
                "tool_name":      event.tool_name,
                "outcome":        event.outcome,
                "severity":       event.severity,
                "duration_ms":    event.duration_ms,
                "trace_id":       event.trace_id,
                "session_id":     event.session_id,
                "caller_ip":      event.caller_ip,
                "error_message":  event.error_message,
                "policy_decision": event.policy_decision,
            }
            yield json.dumps(record) + "\n"

    return StreamingResponse(
        generate(),
        media_type="application/x-ndjson",
        headers={"Content-Disposition": "attachment; filename=mcp_audit_export.ndjson"},
    )


# ── Summary / dashboard stats ─────────────────────────────────────────────────

@router.get("/summary", response_model=AuditSummary)
async def summary(
    from_ts: Optional[datetime] = Query(default=None),
    to_ts:   Optional[datetime] = Query(default=None),
    db: AsyncSession = Depends(get_db),
    _auth = Depends(_require_read_key),
):
    """
    Aggregate stats: outcome counts, top tools, top clients, avg latency.
    Feed this into Grafana, Datadog dashboards, or compliance reports.
    """
    data = await get_summary(db, from_ts=from_ts, to_ts=to_ts)
    return AuditSummary(**data)
