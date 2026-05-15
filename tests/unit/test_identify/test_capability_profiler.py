import pytest
from src.identify.capability_profiler import CapabilityProfiler

def test_capability_profiler_authorized():
    # 'agent-007' has 'read_file' in the mock DB
    assert CapabilityProfiler.is_authorized("agent-007", "read_file") is True

def test_capability_profiler_unauthorized():
    # 'agent-007' does NOT have 'delete_database'
    assert CapabilityProfiler.is_authorized("agent-007", "delete_database") is False

def test_capability_profiler_unknown_agent():
    assert CapabilityProfiler.is_authorized("unknown-agent", "read_file") is False

def test_capability_profiler_add_capability():
    assert CapabilityProfiler.is_authorized("agent-rogue", "execute_sql") is False
    CapabilityProfiler.add_capability("agent-rogue", "execute_sql")
    assert CapabilityProfiler.is_authorized("agent-rogue", "execute_sql") is True
