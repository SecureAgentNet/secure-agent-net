import pytest
from unittest.mock import MagicMock, patch
from secureagentnet.decide.hitl import HITLApprovalGate, HITLDecision, get_hitl_gate


class TestHITLApprovalGate:
    def setup_method(self):
        self.gate = HITLApprovalGate()
        self.gate._pending_requests.clear()
        self.gate._callbacks.clear()

    def test_create_pending_request(self):
        rid = self.gate.create_pending_request(
            "req-001", "agent-1", "execute_sql",
            "users_table", "Query users", 0.5, "Medium risk SQL query",
        )
        assert rid == "req-001"
        req = self.gate.get_pending_request(rid)
        assert req["status"] == "pending"
        assert req["risk_score"] == 0.5
        assert req["action_name"] == "execute_sql"

    def test_approve_request(self):
        rid = self.gate.create_pending_request("req-002", "a", "read", "/tmp", "test", 0.4, "ok")
        decision = self.gate.approve(rid, "operator")
        assert decision == HITLDecision.APPROVED
        req = self.gate.get_pending_request(rid)
        assert req["status"] == "approved"
        assert req["decided_by"] == "operator"

    def test_deny_request(self):
        rid = self.gate.create_pending_request("req-003", "a", "delete", "/etc", "bad", 0.6, "risky")
        decision = self.gate.deny(rid, "operator")
        assert decision == HITLDecision.DENIED
        req = self.gate.get_pending_request(rid)
        assert req["status"] == "denied"

    def test_timeout_denies_request(self):
        rid = self.gate.create_pending_request("req-004", "a", "cmd", "/sh", "test", 0.5, "ok")
        decision = self.gate.wait_for_decision(rid, timeout=0.1)
        assert decision == HITLDecision.TIMED_OUT
        req = self.gate.get_pending_request(rid)
        assert req["status"] == "denied"

    def test_requires_approval_low_risk(self):
        assert not self.gate.requires_approval(0.1)

    def test_requires_approval_medium_risk(self):
        assert self.gate.requires_approval(0.5)

    def test_requires_approval_high_risk(self):
        assert not self.gate.requires_approval(0.85)

    def test_double_approve_ignored(self):
        rid = self.gate.create_pending_request("r-d", "a", "x", "/", "t", 0.5, "ok")
        self.gate.approve(rid)
        decision = self.gate.approve(rid)
        assert decision == HITLDecision.APPROVED

    def test_get_all_pending(self):
        r1 = self.gate.create_pending_request("r1", "a1", "x", "/", "t1", 0.4, "ok")
        r2 = self.gate.create_pending_request("r2", "a2", "y", "/", "t2", 0.5, "ok")
        self.gate.approve(r1)
        pending = self.gate.get_all_pending()
        assert len(pending) == 1
        assert pending[0]["request_id"] == r2

    def test_cleanup_removes_request(self):
        rid = self.gate.create_pending_request("clean", "a", "x", "/", "t", 0.5, "ok")
        self.gate.cleanup(rid)
        assert self.gate.get_pending_request(rid) is None

    def test_singleton_get_hitl_gate(self):
        g1 = get_hitl_gate()
        g2 = get_hitl_gate()
        assert g1 is g2

    def test_callback_invoked_on_approve(self):
        results = []
        rid = self.gate.create_pending_request("cb1", "a", "x", "/", "t", 0.5, "ok")
        self.gate.on_decision(rid, lambda d: results.append(d))
        self.gate.approve(rid)
        assert results == [HITLDecision.APPROVED]

    def test_callback_invoked_on_deny(self):
        results = []
        rid = self.gate.create_pending_request("cb2", "a", "x", "/", "t", 0.5, "ok")
        self.gate.on_decision(rid, lambda d: results.append(d))
        self.gate.deny(rid)
        assert results == [HITLDecision.DENIED]

    def test_pending_count_counts_only_undecided_requests(self):
        """pending_count is the review backlog, so a decision must clear it.

        It previously returned len(self._pending_requests) — every request the
        process had ever created, decided or not — so the number only ever grew.
        That feeds `GET /v1/hitl/pending`'s count and the `san_hitl_pending`
        Prometheus gauge, where a monotonically-rising "pending" is just wrong.
        """
        assert self.gate.pending_count == 0
        self.gate.create_pending_request("c1", "a", "x", "/", "t", 0.5, "ok")
        self.gate.create_pending_request("c2", "a", "x", "/", "t", 0.5, "ok")
        assert self.gate.pending_count == 2

        self.gate.approve("c1")
        assert self.gate.pending_count == 1, "an approved request is no longer pending"

        self.gate.deny("c2")
        assert self.gate.pending_count == 0, "a denied request is no longer pending"

        # The requests still exist and remember how they were resolved — clearing
        # the backlog must not lose the decision.
        assert self.gate.get_pending_request("c1")["status"] == HITLDecision.APPROVED.value
        assert self.gate.get_pending_request("c2")["status"] == HITLDecision.DENIED.value
