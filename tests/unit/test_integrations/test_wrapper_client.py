from unittest.mock import MagicMock

from secureagentnet.integrations.wrappers.client import InterceptClient, secureagentnet_intercept


def test_intercept_client_success(tmp_path, monkeypatch):
    monkeypatch.setenv("SAN_DATA_DIR", str(tmp_path))
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"status": "success", "correlation_id": "corr-1"}
    mock_resp.raise_for_status.return_value = None
    monkeypatch.setattr("requests.post", lambda *args, **kwargs: mock_resp)

    client = InterceptClient(host="127.0.0.1", port=17541)
    result = client.intercept("agent-1", "read_file", "/tmp/x", "read file")
    assert result["status"] == "success"


def test_secureagentnet_intercept_helper(tmp_path, monkeypatch):
    monkeypatch.setenv("SAN_DATA_DIR", str(tmp_path))
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"status": "blocked", "correlation_id": "corr-2", "reason": "unauthorized"}
    mock_resp.raise_for_status.return_value = None
    monkeypatch.setattr("requests.post", lambda *args, **kwargs: mock_resp)

    result = secureagentnet_intercept("agent-1", "execute", "shell", "run shell")
    assert result["status"] == "blocked"


class TestVerdictGate:
    """The wrappers must run a governed tool only on an explicit approval.

    Regression guard for a fail-open: the wrappers used to test for the two
    refusal statuses they knew about ("blocked", "error") and execute otherwise.
    The pipeline also returns "escalated" when DECIDE parks an action for human
    approval — that matched neither branch, so the tool ran anyway. The sandbox
    had already been torn down unexecuted and the audit log recorded a denial,
    while the tool body executed locally regardless.
    """

    def test_only_success_is_allowed(self):
        from secureagentnet.integrations.wrappers.client import is_allowed

        assert is_allowed({"status": "success"}) is True
        for refused in ("blocked", "error", "escalated", "pending", "", None):
            assert is_allowed({"status": refused}) is False, refused
        # A status the pipeline grows later must refuse, not execute.
        assert is_allowed({"status": "some_future_verdict"}) is False
        assert is_allowed({}) is False

    def test_escalated_never_reaches_the_tool(self):
        """The exact shape DECIDE returns when it escalates to human review."""
        from secureagentnet.integrations.wrappers.langchain import (
            SecureAgentNetLangChainTool,
        )
        from langchain_core.tools import StructuredTool

        executed = []

        def _real_tool(term: str = "") -> str:
            executed.append(term)
            return "SENSITIVE RESULT"

        # The wrapper's `client` field is typed, so patch a real one rather than
        # substituting a duck-typed stand-in.
        client = InterceptClient()
        client.intercept = lambda **kwargs: {   # type: ignore[method-assign]
            "status": "escalated",
            "reason": "HITL approval required for: search_files "
                      "(Action deviates from the original mandate)",
            "risk_score": 0.52,
            "evaluated_by": "HITLApprovalGate",
            "phase": "DECIDE",
            "metadata": {"hitl_request_id": "req-123", "hitl_required": True},
        }

        tool = SecureAgentNetLangChainTool(
            agent_id="agent-1",
            tool=StructuredTool.from_function(func=_real_tool, name="search_files",
                                              description="search"),
            client=client,
        )
        out = tool.invoke({"term": "BEGIN RSA PRIVATE KEY"})

        assert executed == [], "escalated verdict executed the tool — fail-open"
        assert "SENSITIVE RESULT" not in out
        assert "HELD" in out
        assert "req-123" in out, "the reviewer needs the request id to act on it"

    def test_denial_message_carries_remediation(self):
        from secureagentnet.integrations.wrappers.client import format_denial

        out = format_denial({
            "status": "blocked",
            "reason": "Agent lacks capability: send_email",
            "remediation": ["Granted capabilities: search_files",
                            "  san agent add-cap abc send_email"],
        })
        assert "BLOCKED" in out
        assert "san agent add-cap abc send_email" in out
