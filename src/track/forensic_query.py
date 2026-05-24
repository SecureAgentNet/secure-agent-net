import logging
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta

from src.track.log_indexer import LogIndexer
from src.identify.identity_registry import IdentityRegistry

logger = logging.getLogger("SecureAgentNet.Track.ForensicQuery")


class ForensicQueryEngine:
    @staticmethod
    def query_agent_timeline(agent_id: str, last_minutes: Optional[int] = None) -> List[Dict[str, Any]]:
        events = LogIndexer.query_by_agent(agent_id)
        if last_minutes:
            cutoff = datetime.utcnow() - timedelta(minutes=last_minutes)
            events = [e for e in events if datetime.fromisoformat(e.get("timestamp", "")).replace(tzinfo=None) >= cutoff]
        return events

    @staticmethod
    def query_phase_activity(phase: str, limit: int = 50) -> List[Dict[str, Any]]:
        return [e for e in reversed(LogIndexer._events) if e.get("phase") == phase][:limit]

    @staticmethod
    def search_events(query: str, limit: int = 50) -> List[Dict[str, Any]]:
        return LogIndexer.search(query, limit)

    @staticmethod
    def get_system_summary() -> Dict[str, Any]:
        events = LogIndexer._events
        total_events = len(events)
        phase_counts = LogIndexer.count_by_phase()
        severity_counts = LogIndexer.count_by_severity()

        blocked = len([e for e in events if e.get("event_type", "").startswith("blocked") or e.get("decision") == "DENY"])
        approved = len([e for e in events if e.get("decision") == "APPROVE"])
        agent_count = IdentityRegistry.get_active_count()
        total_agents = IdentityRegistry.get_total_count()

        return {
            "total_events": total_events,
            "active_agents": agent_count,
            "total_agents": total_agents,
            "blocked_actions": blocked,
            "approved_actions": approved,
            "phases": phase_counts,
            "severity_distribution": severity_counts,
        }

    @staticmethod
    def export_events(format: str = "json") -> str:
        import json
        events = LogIndexer.get_recent(1000)
        if format == "json":
            return json.dumps(events, indent=2, default=str)
        elif format == "csv":
            import csv
            import io
            output = io.StringIO()
            if not events:
                return ""
            writer = csv.DictWriter(output, fieldnames=events[0].keys())
            writer.writeheader()
            writer.writerows(events)
            return output.getvalue()
        return json.dumps(events, default=str)

    @staticmethod
    def get_agent_report(agent_id: str) -> Dict[str, Any]:
        events = LogIndexer.query_by_agent(agent_id)
        agent = IdentityRegistry.get_agent(agent_id)

        blocked = len([e for e in events if e.get("decision") == "DENY"])
        approved = len([e for e in events if e.get("decision") == "APPROVE"])
        total = len(events)

        return {
            "agent_id": agent_id,
            "agent_name": agent.get("name", "Unknown") if agent else "Unknown",
            "agent_type": agent.get("type", "Unknown") if agent else "Unknown",
            "trust_score": agent.get("trust_score", 0) if agent else 0,
            "status": agent.get("status", "unknown") if agent else "unknown",
            "total_events": total,
            "blocked": blocked,
            "approved": approved,
            "block_rate": round(blocked / total * 100, 2) if total > 0 else 0,
            "events": events[-50:],
        }

    @staticmethod
    def get_decision_log() -> List[Dict[str, Any]]:
        return [e for e in LogIndexer._events if e.get("phase") == "DECIDE"]
