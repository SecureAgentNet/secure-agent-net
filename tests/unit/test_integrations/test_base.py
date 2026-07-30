from secureagentnet.integrations.base import (
    BLOCKED_PREFIX,
    ESCALATED_PREFIX,
    format_command,
    interpret_result,
    secure_callable,
)


class FakeExecutor:
    """Records the call it receives and returns a preset result dict."""

    def __init__(self, result):
        self.result = result
        self.calls = []

    def execute(self, *, action_name, target_resource, command, intent_summary, payload):
        self.calls.append(
            dict(
                action_name=action_name,
                target_resource=target_resource,
                command=command,
                intent_summary=intent_summary,
                payload=payload,
            )
        )
        return self.result


def test_format_command_positional_and_kwargs():
    assert format_command(("a", "b"), {}) == "a b"
    assert format_command((), {"path": "/tmp"}) == "--path=/tmp"
    assert format_command(("ls",), {"all": True}) == "ls --all=True"


def test_interpret_result_success_data_dict():
    assert interpret_result({"status": "success", "data": {"stdout": "ok", "stderr": ""}}) == "ok"


def test_interpret_result_success_flat_stdout():
    assert interpret_result({"status": "success", "stdout": "hello"}) == "hello"


def test_interpret_result_blocked():
    out = interpret_result({"status": "blocked", "reason": "prompt injection"})
    assert out.startswith(BLOCKED_PREFIX)
    assert "prompt injection" in out


def test_interpret_result_escalated():
    out = interpret_result({"status": "escalated", "reason": "needs approval"})
    assert out.startswith(ESCALATED_PREFIX)
    assert "needs approval" in out


def test_secure_callable_success_returns_output():
    ex = FakeExecutor({"status": "success", "data": {"stdout": "done"}})

    def my_tool(x):
        """does a thing"""
        return x

    secured = secure_callable(my_tool, action_name="execute_sql", target_resource="db", executor=ex)
    assert secured("SELECT 1") == "done"

    # routed correctly
    call = ex.calls[0]
    assert call["action_name"] == "execute_sql"
    assert call["target_resource"] == "db"
    assert call["command"] == "SELECT 1"
    assert call["payload"]["args"] == ["SELECT 1"]


def test_secure_callable_blocked_returns_message():
    ex = FakeExecutor({"status": "blocked", "reason": "rm -rf denied"})

    def danger():
        return "should not run"

    secured = secure_callable(danger, executor=ex)
    out = secured()
    assert out.startswith(BLOCKED_PREFIX)
    assert "rm -rf denied" in out


def test_secure_callable_escalated_returns_message():
    ex = FakeExecutor({"status": "escalated", "reason": "medium risk"})
    secured = secure_callable(lambda: None, executor=ex)
    assert secured().startswith(ESCALATED_PREFIX)


def test_secure_callable_preserves_metadata():
    ex = FakeExecutor({"status": "success", "stdout": ""})

    def my_named_tool():
        """my doc"""

    secured = secure_callable(my_named_tool, executor=ex)
    assert secured.__name__ == "my_named_tool"
    assert secured.__doc__ == "my doc"
    assert secured.__wrapped__ is my_named_tool


def test_secure_callable_empty_args_uses_tool_name_as_command():
    ex = FakeExecutor({"status": "success", "stdout": ""})

    def ping():
        pass

    secure_callable(ping, executor=ex)()
    assert ex.calls[0]["command"] == "ping"


# ── enforce_only (adjudicate-only) mode ──────────────────────────────────────
class AdjudicatingFakeExecutor:
    """Fake that supports the decision-only ``adjudicate`` path."""

    def __init__(self, status, reason="because"):
        self.result = {"status": status, "reason": reason}
        self.calls = []

    def adjudicate(self, *, action_name, target_resource, intent_summary, payload):
        self.calls.append(dict(action_name=action_name, target_resource=target_resource,
                               intent_summary=intent_summary, payload=payload))
        return self.result


def test_enforce_only_allow_runs_the_real_body():
    ex = AdjudicatingFakeExecutor("allowed")
    ran = {}

    def send(to, body):
        """send an email"""
        ran["to"] = to
        return f"sent to {to}"

    secured = secure_callable(send, action_name="send_email", enforce_only=True, executor=ex)
    out = secured(to="alice@ourcompany.com", body="hi")
    # On approval the real side effect runs in-process (not a sandbox stdout).
    assert out == "sent to alice@ourcompany.com"
    assert ran["to"] == "alice@ourcompany.com"


def test_enforce_only_block_does_not_run_body():
    ex = AdjudicatingFakeExecutor("blocked", reason="exfiltration to external address")
    ran = {"called": False}

    def send(to, body):
        ran["called"] = True
        return "sent"

    secured = secure_callable(send, action_name="send_email", enforce_only=True, executor=ex)
    out = secured(to="attacker@evil.example", body="secret")
    assert out.startswith(BLOCKED_PREFIX)
    assert "exfiltration" in out
    assert ran["called"] is False  # the real body never executed


def test_enforce_only_escalated_message():
    ex = AdjudicatingFakeExecutor("escalated", reason="medium risk")
    secured = secure_callable(lambda to: "sent", action_name="send_email",
                              enforce_only=True, executor=ex)
    assert secured(to="x@y.z").startswith(ESCALATED_PREFIX)


def test_target_resolver_derives_resource_from_args():
    ex = AdjudicatingFakeExecutor("allowed")
    secured = secure_callable(
        lambda to, body: "ok", action_name="send_email", enforce_only=True,
        target_resolver=lambda args, kwargs: kwargs.get("to"), executor=ex)
    secured(to="attacker@evil.example", body="k")
    # DECIDE judged *this call's* recipient, not a static per-tool resource.
    assert ex.calls[0]["target_resource"] == "attacker@evil.example"
