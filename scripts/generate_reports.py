#!/usr/bin/env python3
"""Generate evaluation reports from SecureAgentNet test data."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import logging
import json
from datetime import datetime

from secureagentnet.track.forensic_query import ForensicQueryEngine
from secureagentnet.track.log_indexer import LogIndexer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SecureAgentNet.Reports")


def generate_performance_report() -> dict:
    events = LogIndexer.get_recent(1000)
    if not events:
        return {"error": "No events recorded"}

    decisions = [e for e in events if e.get("phase") == "DECIDE"]
    blocked = len([d for d in decisions if d.get("final_decision") == "DENY" or d.get("decision") == "DENY"])
    approved = len([d for d in decisions if d.get("final_decision") == "APPROVE" or d.get("decision") == "APPROVE"])

    return {
        "generated_at": datetime.utcnow().isoformat(),
        "total_events": len(events),
        "total_phases": len(set(e.get("phase") for e in events if e.get("phase"))),
        "decisions": {
            "total": len(decisions),
            "blocked": blocked,
            "approved": approved,
            "block_rate": round(blocked / len(decisions) * 100, 2) if decisions else 0,
        },
        "summary": ForensicQueryEngine.get_system_summary(),
    }


def generate_security_report() -> dict:
    summary = ForensicQueryEngine.get_system_summary()
    return {
        "generated_at": datetime.utcnow().isoformat(),
        "system_summary": summary,
        "security_status": {
            "total_events_audited": summary.get("total_events", 0),
            "blocked_actions": summary.get("blocked_actions", 0),
            "active_agents_monitored": summary.get("active_agents", 0),
        },
    }


def save_report(report: dict, filename: str):
    output_dir = Path(__file__).parent.parent / "reports"
    output_dir.mkdir(exist_ok=True)
    filepath = output_dir / filename
    with open(filepath, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info(f"Report saved: {filepath}")


if __name__ == "__main__":
    from secureagentnet.identify.identity_registry import IdentityRegistry
    IdentityRegistry.initialize()

    perf_report = generate_performance_report()
    save_report(perf_report, "performance_report.json")

    sec_report = generate_security_report()
    save_report(sec_report, "security_report.json")

    logger.info("Reports generated successfully.")
