import json
import pytest
from datetime import datetime, timezone
from secureagentnet.track.forensic_query import ForensicQueryEngine
from secureagentnet.track.log_indexer import LogIndexer
from secureagentnet.identify.identity_registry import IdentityRegistry
from secureagentnet.core.constants import PipelinePhase, EventSeverity


class TestForensicQueryEngine:
    @pytest.fixture
    def registered_agent(self):
        IdentityRegistry._agents = {}
        IdentityRegistry._initialized = False
        IdentityRegistry.initialize()
        agent = IdentityRegistry.register_agent({
            "name": "test-agent",
            "type": "Custom",
            "public_key": "pk-001",
        })
        return agent

    def make_event(self, agent_id="test-agent", **overrides):
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "event_type": "pipeline_started",
            "phase": PipelinePhase.IDENTIFY.value,
            "severity": EventSeverity.INFO.value,
            "summary": "Test event",
            "correlation_id": "corr-abc",
            "decision": "APPROVE",
        }
        event.update(overrides)
        return event

    def test_get_system_summary(self, registered_agent):
        LogIndexer.index_event(self.make_event(decision="APPROVE"))
        LogIndexer.index_event(self.make_event(decision="DENY", event_type="blocked_action"))
        LogIndexer.index_event(self.make_event(decision="DENY"))
        summary = ForensicQueryEngine.get_system_summary()
        assert summary["total_events"] == 3
        assert summary["active_agents"] == 1
        assert summary["total_agents"] == 1
        assert summary["blocked_actions"] == 2
        assert summary["approved_actions"] == 1
        assert PipelinePhase.IDENTIFY.value in summary["phases"]
        assert EventSeverity.INFO.value in summary["severity_distribution"]

    def test_get_system_summary_empty(self):
        IdentityRegistry._agents = {}
        IdentityRegistry._initialized = False
        IdentityRegistry.initialize()
        LogIndexer._events = []
        summary = ForensicQueryEngine.get_system_summary()
        assert summary["total_events"] == 0
        assert summary["active_agents"] == 0
        assert summary["total_agents"] == 0
        assert summary["blocked_actions"] == 0
        assert summary["approved_actions"] == 0

    def test_export_events_json(self, registered_agent):
        LogIndexer.index_event(self.make_event(decision="APPROVE"))
        LogIndexer.index_event(self.make_event(decision="DENY"))
        result = ForensicQueryEngine.export_events(format="json")
        data = json.loads(result)
        assert isinstance(data, list)
        assert len(data) == 2
        assert data[0]["decision"] == "DENY"

    def test_export_events_json_default(self, registered_agent):
        LogIndexer.index_event(self.make_event())
        result = ForensicQueryEngine.export_events()
        data = json.loads(result)
        assert len(data) == 1

    def test_export_events_csv(self, registered_agent):
        LogIndexer.index_event(self.make_event())
        result = ForensicQueryEngine.export_events(format="csv")
        assert "timestamp" in result
        assert "agent_id" in result
        assert "test-agent" in result

    def test_export_events_csv_empty(self):
        LogIndexer._events = []
        result = ForensicQueryEngine.export_events(format="csv")
        assert result == ""

    def test_export_events_json_empty(self):
        LogIndexer._events = []
        result = ForensicQueryEngine.export_events(format="json")
        assert result == "[]"

    def test_get_agent_report(self, registered_agent):
        agent_id = registered_agent["agent_id"]
        LogIndexer.index_event(self.make_event(agent_id=agent_id, decision="APPROVE"))
        LogIndexer.index_event(self.make_event(agent_id=agent_id, decision="DENY"))
        LogIndexer.index_event(self.make_event(agent_id=agent_id, decision="APPROVE"))
        report = ForensicQueryEngine.get_agent_report(agent_id)
        assert report["agent_id"] == agent_id
        assert report["agent_name"] == "test-agent"
        assert report["agent_type"] == "Custom"
        assert report["trust_score"] == 50.0
        assert report["status"] == "active"
        assert report["total_events"] == 3
        assert report["blocked"] == 1
        assert report["approved"] == 2
        assert report["block_rate"] == 33.33
        assert len(report["events"]) == 3

    def test_get_agent_report_no_agent(self):
        report = ForensicQueryEngine.get_agent_report("nonexistent-id")
        assert report["agent_id"] == "nonexistent-id"
        assert report["agent_name"] == "Unknown"
        assert report["total_events"] == 0
        assert report["block_rate"] == 0

    def test_get_agent_report_no_events(self, registered_agent):
        agent_id = registered_agent["agent_id"]
        report = ForensicQueryEngine.get_agent_report(agent_id)
        assert report["total_events"] == 0
        assert report["block_rate"] == 0

    def test_query_agent_timeline(self, registered_agent):
        agent_id = registered_agent["agent_id"]
        LogIndexer.index_event(self.make_event(agent_id=agent_id))
        LogIndexer.index_event(self.make_event(agent_id="other-agent"))
        events = ForensicQueryEngine.query_agent_timeline(agent_id)
        assert len(events) == 1

    def test_query_phase_activity(self, registered_agent):
        LogIndexer.index_event(self.make_event(phase=PipelinePhase.IDENTIFY.value))
        LogIndexer.index_event(self.make_event(phase=PipelinePhase.DECIDE.value))
        events = ForensicQueryEngine.query_phase_activity(PipelinePhase.DECIDE.value)
        assert len(events) == 1

    def test_search_events(self, registered_agent):
        LogIndexer.index_event(self.make_event(summary="Read file completed"))
        LogIndexer.index_event(self.make_event(summary="Write file completed"))
        results = ForensicQueryEngine.search_events("Read")
        assert len(results) == 1

    def test_get_decision_log(self, registered_agent):
        LogIndexer.index_event(self.make_event(phase=PipelinePhase.DECIDE.value, decision="APPROVE"))
        LogIndexer.index_event(self.make_event(phase=PipelinePhase.IDENTIFY.value))
        decisions = ForensicQueryEngine.get_decision_log()
        assert len(decisions) == 1
        assert decisions[0]["phase"] == PipelinePhase.DECIDE.value
