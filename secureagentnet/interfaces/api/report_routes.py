import logging
from datetime import datetime, timezone
from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional

from secureagentnet.database.connection import get_db_session
from secureagentnet.database.models import AuditLogEntry
from secureagentnet.track.log_indexer import LogIndexer
from secureagentnet.interfaces.api.auth import get_current_operator

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/reports", tags=["Reports"])


class ReportEntry(BaseModel):
    report_id: str
    title: str
    category: str
    severity: str
    agent_id: Optional[str] = None
    agent_name: Optional[str] = None
    summary: str
    timestamp: str
    status: str = "open"
    thread_count: int = 0

    class Config:
        from_attributes = True


class ThreadMessage(BaseModel):
    message_id: str
    report_id: str
    author: str
    content: str
    timestamp: str


class AddThreadRequest(BaseModel):
    report_id: str
    author: str
    content: str


# In-memory thread storage (simple for now, can be moved to DB)
_threads: dict[str, list[dict]] = {}


def _build_report(entry: dict, idx: int) -> dict:
    severity_map = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "WARNING": "medium", "LOW": "low", "INFO": "low"}
    category_map = {
        "IDENTIFY": "identity", "TRACK": "audit", "CONTAIN": "sandbox",
        "DECIDE": "policy", "AUTH": "auth", "EXECUTION": "execution",
    }
    severity = severity_map.get(entry.get("severity", "INFO"), "low")
    category = category_map.get(entry.get("phase", "EXECUTION"), entry.get("event_type", "general"))
    return {
        "report_id": f"rpt-{idx:04d}",
        "title": f"[{entry.get('phase', 'UNKNOWN')}] {entry.get('event_type', 'Event')}",
        "category": category,
        "severity": severity,
        "agent_id": entry.get("agent_id"),
        "agent_name": entry.get("agent_name", "unknown"),
        "summary": entry.get("details", "No details available"),
        "timestamp": entry.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "status": "open" if severity in ("critical", "high") else "resolved",
        "thread_count": len(_threads.get(f"rpt-{idx:04d}", [])),
    }


@router.get("", response_model=list[ReportEntry])
def list_reports(_operator: dict = Depends(get_current_operator)):
    events = LogIndexer._events
    result = []
    for i, event in enumerate(events[-50:]):  # last 50 events
        result.append(_build_report(event, len(events) - 50 + i))
    return sorted(result, key=lambda r: r["timestamp"], reverse=True)


@router.get("/threats", response_model=list[ReportEntry])
def get_threat_history(_operator: dict = Depends(get_current_operator)):
    events = LogIndexer._events
    threats = [e for e in events if e.get("severity") in ("CRITICAL", "HIGH")]
    result = [_build_report(e, i) for i, e in enumerate(threats[-20:])]
    return sorted(result, key=lambda r: r["timestamp"], reverse=True)


@router.get("/{report_id}/thread", response_model=list[ThreadMessage])
def get_report_thread(report_id: str, _operator: dict = Depends(get_current_operator)):
    return [ThreadMessage(**m) for m in _threads.get(report_id, [])]


@router.post("/{report_id}/thread", status_code=201, response_model=ThreadMessage)
def add_thread_message(report_id: str, body: AddThreadRequest, _operator: dict = Depends(get_current_operator)):
    msg = {
        "message_id": str(uuid4())[:8],
        "report_id": report_id,
        "author": body.author,
        "content": body.content,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    _threads.setdefault(report_id, []).append(msg)
    logger.info("Thread message added to report %s by %s", report_id, body.author)
    return ThreadMessage(**msg)


@router.get("/{report_id}/pdf", status_code=200)
def generate_report_pdf(report_id: str, _operator: dict = Depends(get_current_operator)):
    events = LogIndexer._events
    report = None
    for i, e in enumerate(events):
        if _build_report(e, i)["report_id"] == report_id:
            report = _build_report(e, i)
            break

    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    threads = _threads.get(report_id, [])

    html = f"""<!DOCTYPE html>
<html><head><title>{report['title']}</title>
<style>body{{font-family:monospace;background:#0f131d;color:#dfe2f1;padding:40px;}}
h1{{color:#4cd7f6;}}h2{{color:#bcc9cd;}}table{{width:100%;border-collapse:collapse;}}
td,th{{padding:8px;border:1px solid rgba(255,255,255,0.1);text-align:left;}}
.badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold;}}
.critical{{background:rgba(239,68,68,0.2);color:#ef4444;}}
.high{{background:rgba(245,158,11,0.2);color:#f59e0b;}}
.medium{{background:rgba(16,185,129,0.2);color:#10b981;}}
.low{{background:rgba(0,229,255,0.2);color:#00e5ff;}}
</style></head><body>
<h1>{report['title']}</h1>
<table>
<tr><td>Category</td><td>{report['category']}</td></tr>
<tr><td>Severity</td><td><span class="badge {report['severity']}">{report['severity'].upper()}</span></td></tr>
<tr><td>Agent</td><td>{report['agent_name']} ({report['agent_id']})</td></tr>
<tr><td>Timestamp</td><td>{report['timestamp']}</td></tr>
<tr><td>Status</td><td>{report['status']}</td></tr>
</table>
<h2>Summary</h2><p>{report['summary']}</p>
<h2>Collaboration Thread ({len(threads)} messages)</h2>
{"".join(f'<div style="margin-bottom:12px;padding:8px;background:rgba(255,255,255,0.03);border-radius:4px"><strong>{m["author"]}</strong> <small>{m["timestamp"]}</small><br>{m["content"]}</div>' for m in threads) if threads else '<p>No thread messages.</p>'}
</body></html>"""

    from fastapi.responses import HTMLResponse
    return HTMLResponse(content=html, headers={"X-Report-Generated": "true"})
