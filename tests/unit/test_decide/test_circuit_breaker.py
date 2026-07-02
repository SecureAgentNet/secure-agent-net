import pytest
import time
from secureagentnet.decide.circuit_breaker import CircuitBreaker

def test_circuit_breaker_flow():
    # Setup a fast-tripping breaker for tests
    cb = CircuitBreaker(failure_threshold=3, time_window_seconds=2, reset_timeout_seconds=2)
    agent_id = "test-agent-cb"
    
    # 1. Normal state (CLOSED)
    is_allowed, msg = cb.check_access(agent_id)
    assert is_allowed is True
    
    # 2. Record 2 failures (under threshold)
    cb.record_failure(agent_id)
    cb.record_failure(agent_id)
    
    is_allowed, msg = cb.check_access(agent_id)
    assert is_allowed is True # Circuit still closed
    
    # 3. Record 3rd failure (trips circuit)
    cb.record_failure(agent_id)
    
    is_allowed, msg = cb.check_access(agent_id)
    assert is_allowed is False
    assert "suspended" in msg
    
    # 4. Wait for reset timeout
    time.sleep(2.1)
    
    # 5. Circuit should reset
    is_allowed, msg = cb.check_access(agent_id)
    assert is_allowed is True
    assert "Circuit closed" in msg
