import logging
from typing import Dict, Any, List
from datetime import datetime

from src.core.constants import PipelinePhase, EventSeverity
from src.database.repositories import AuditLogRepository

logger = logging.getLogger("SecureAgentNet.Track.Indexer")


class LogIndexer:
    _events: List[Dict[str, Any]] = []
    _max_events = 10000

    @classmethod
    def _persist(cls):
        if cls._events:
            AuditLogRepository.append(cls._events[-1])

    @classmethod
    def _load(cls):
        cls._events = AuditLogRepository.load_all()

    @classmethod
    def initialize(cls):
        cls._events = []
        cls._load()
        logger.info("LogIndexer initialized.")

    @classmethod
    def index_event(cls, event: Dict[str, Any]) -> int:
        cls._events.append(event)
        if len(cls._events) > cls._max_events:
            cls._events.pop(0)
        cls._persist()
        return len(cls._events) - 1

    @classmethod
    def search(cls, query: str, limit: int = 100) -> List[Dict[str, Any]]:
        query_lower = query.lower()
        results = []
        for event in reversed(cls._events):
            searchable = str(event.get("summary", "")) + " " + str(event.get("event_type", ""))
            if query_lower in searchable.lower():
                results.append(event)
                if len(results) >= limit:
                    break
        return results

    @classmethod
    def query_by_agent(cls, agent_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        results = [e for e in reversed(cls._events) if e.get("agent_id") == agent_id]
        return results[:limit]

    @classmethod
    def query_by_phase(cls, phase: PipelinePhase, limit: int = 100) -> List[Dict[str, Any]]:
        results = [e for e in reversed(cls._events) if e.get("phase") == phase.value]
        return results[:limit]

    @classmethod
    def query_by_severity(cls, severity: EventSeverity, limit: int = 100) -> List[Dict[str, Any]]:
        results = [e for e in reversed(cls._events) if e.get("severity") == severity.value]
        return results[:limit]

    @classmethod
    def query_by_time_range(cls, start: datetime, end: datetime, limit: int = 100) -> List[Dict[str, Any]]:
        results = []
        for event in reversed(cls._events):
            ts_str = event.get("timestamp", "")
            try:
                ts = datetime.fromisoformat(ts_str)
                if start <= ts <= end:
                    results.append(event)
                    if len(results) >= limit:
                        break
            except (ValueError, TypeError):
                continue
        return results

    @classmethod
    def query_by_correlation_id(cls, correlation_id: str) -> List[Dict[str, Any]]:
        return [e for e in cls._events if e.get("correlation_id") == correlation_id]

    @classmethod
    def count_by_phase(cls) -> Dict[str, int]:
        counts = {}
        for event in cls._events:
            phase = event.get("phase", "UNKNOWN")
            counts[phase] = counts.get(phase, 0) + 1
        return counts

    @classmethod
    def count_by_severity(cls) -> Dict[str, int]:
        counts = {}
        for event in cls._events:
            severity = event.get("severity", "UNKNOWN")
            counts[severity] = counts.get(severity, 0) + 1
        return counts

    @classmethod
    def get_recent(cls, count: int = 50) -> List[Dict[str, Any]]:
        return list(reversed(cls._events))[:count]

    @classmethod
    def clear(cls):
        cls._events.clear()
        from src.database.connection import get_db_session
        from src.database import models
        from sqlalchemy import delete as sa_delete
        try:
            with get_db_session() as session:
                session.execute(sa_delete(models.AuditLogEntry))
        except Exception:
            pass
        logger.info("LogIndexer cleared.")
