import pytest
from datetime import datetime, timezone
from secureagentnet.track.log_indexer import LogIndexer
from secureagentnet.core.constants import PipelinePhase, EventSeverity


class TestLogIndexer:
    @pytest.fixture(autouse=True)
    def reset(self):
        LogIndexer._events = []
        LogIndexer._max_events = 10000

    def make_event(self, **overrides):
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent_id": "agent-1",
            "event_type": "pipeline_started",
            "phase": PipelinePhase.IDENTIFY.value,
            "severity": EventSeverity.INFO.value,
            "summary": "Test event",
            "correlation_id": "corr-abc123",
            "decision": "APPROVE",
        }
        event.update(overrides)
        return event

    def test_index_event(self):
        event = self.make_event()
        idx = LogIndexer.index_event(event)
        assert idx == 0
        assert len(LogIndexer._events) == 1
        assert LogIndexer._events[0] == event

    def test_index_event_returns_id(self):
        e1 = self.make_event()
        e2 = self.make_event(agent_id="agent-2")
        assert LogIndexer.index_event(e1) == 0
        assert LogIndexer.index_event(e2) == 1

    def test_index_event_respects_max(self):
        LogIndexer._max_events = 2
        LogIndexer.index_event(self.make_event(agent_id="a1"))
        LogIndexer.index_event(self.make_event(agent_id="a2"))
        LogIndexer.index_event(self.make_event(agent_id="a3"))
        assert len(LogIndexer._events) == 2
        assert LogIndexer._events[0]["agent_id"] == "a2"
        assert LogIndexer._events[1]["agent_id"] == "a3"

    def test_search(self):
        LogIndexer.index_event(self.make_event(summary="Read file operation"))
        LogIndexer.index_event(self.make_event(summary="Write file operation"))
        LogIndexer.index_event(self.make_event(summary="Delete database"))
        results = LogIndexer.search("Write")
        assert len(results) == 1
        assert "Write" in results[0]["summary"]

    def test_search_finds_by_event_type(self):
        LogIndexer.index_event(self.make_event(event_type="blocked_action"))
        LogIndexer.index_event(self.make_event(event_type="approved_request"))
        results = LogIndexer.search("blocked")
        assert len(results) == 1

    def test_search_case_insensitive(self):
        LogIndexer.index_event(self.make_event(summary="READ FILE"))
        results = LogIndexer.search("read")
        assert len(results) == 1

    def test_search_respects_limit(self):
        for i in range(10):
            LogIndexer.index_event(self.make_event(summary=f"Event {i}"))
        results = LogIndexer.search("Event", limit=3)
        assert len(results) == 3

    def test_search_no_matches(self):
        LogIndexer.index_event(self.make_event(summary="Hello"))
        assert LogIndexer.search("nonexistent") == []

    def test_query_by_agent(self):
        LogIndexer.index_event(self.make_event(agent_id="agent-1"))
        LogIndexer.index_event(self.make_event(agent_id="agent-2"))
        LogIndexer.index_event(self.make_event(agent_id="agent-1"))
        results = LogIndexer.query_by_agent("agent-1")
        assert len(results) == 2
        for r in results:
            assert r["agent_id"] == "agent-1"

    def test_query_by_agent_no_results(self):
        assert LogIndexer.query_by_agent("no-such-agent") == []

    def test_query_by_phase(self):
        LogIndexer.index_event(self.make_event(phase=PipelinePhase.IDENTIFY.value))
        LogIndexer.index_event(self.make_event(phase=PipelinePhase.DECIDE.value))
        LogIndexer.index_event(self.make_event(phase=PipelinePhase.IDENTIFY.value))
        results = LogIndexer.query_by_phase(PipelinePhase.IDENTIFY)
        assert len(results) == 2

    def test_query_by_severity(self):
        LogIndexer.index_event(self.make_event(severity=EventSeverity.INFO.value))
        LogIndexer.index_event(self.make_event(severity=EventSeverity.WARNING.value))
        LogIndexer.index_event(self.make_event(severity=EventSeverity.INFO.value))
        results = LogIndexer.query_by_severity(EventSeverity.INFO)
        assert len(results) == 2

    def test_count_by_phase(self):
        LogIndexer.index_event(self.make_event(phase=PipelinePhase.IDENTIFY.value))
        LogIndexer.index_event(self.make_event(phase=PipelinePhase.DECIDE.value))
        LogIndexer.index_event(self.make_event(phase=PipelinePhase.IDENTIFY.value))
        counts = LogIndexer.count_by_phase()
        assert counts[PipelinePhase.IDENTIFY.value] == 2
        assert counts[PipelinePhase.DECIDE.value] == 1

    def test_count_by_phase_empty(self):
        assert LogIndexer.count_by_phase() == {}

    def test_count_by_severity(self):
        LogIndexer.index_event(self.make_event(severity=EventSeverity.INFO.value))
        LogIndexer.index_event(self.make_event(severity=EventSeverity.ERROR.value))
        counts = LogIndexer.count_by_severity()
        assert counts[EventSeverity.INFO.value] == 1
        assert counts[EventSeverity.ERROR.value] == 1

    def test_get_recent(self):
        for i in range(5):
            LogIndexer.index_event(self.make_event(agent_id=f"agent-{i}"))
        recent = LogIndexer.get_recent(2)
        assert len(recent) == 2

    def test_get_recent_returns_newest_first(self):
        LogIndexer.index_event(self.make_event(agent_id="first"))
        LogIndexer.index_event(self.make_event(agent_id="second"))
        recent = LogIndexer.get_recent(2)
        assert recent[0]["agent_id"] == "second"
        assert recent[1]["agent_id"] == "first"

    def test_get_recent_less_than_count(self):
        LogIndexer.index_event(self.make_event())
        assert len(LogIndexer.get_recent(50)) == 1

    def test_clear(self):
        LogIndexer.index_event(self.make_event())
        LogIndexer.index_event(self.make_event())
        assert len(LogIndexer._events) == 2
        LogIndexer.clear()
        assert LogIndexer._events == []

    def test_query_by_correlation_id(self):
        LogIndexer.index_event(self.make_event(correlation_id="corr-111"))
        LogIndexer.index_event(self.make_event(correlation_id="corr-222"))
        LogIndexer.index_event(self.make_event(correlation_id="corr-111"))
        results = LogIndexer.query_by_correlation_id("corr-111")
        assert len(results) == 2

    def test_query_by_time_range(self):
        from datetime import timedelta
        now = datetime.now(timezone.utc)
        LogIndexer.index_event(self.make_event(timestamp=(now - timedelta(hours=2)).isoformat()))
        LogIndexer.index_event(self.make_event(timestamp=now.isoformat()))
        start = now - timedelta(hours=1)
        end = now + timedelta(hours=1)
        results = LogIndexer.query_by_time_range(start, end)
        assert len(results) == 1
