"""Adapter tests that run without the frameworks installed.

They exercise the code paths that don't import langchain/crewai/autogen — namely
the class-style (`._run`) and function-style (`.func`) tool wrapping and the
AutoGen ``secure_function`` helper — using fake tool objects + a mock executor.
"""
from secureagentnet.integrations.base import BLOCKED_PREFIX
from secureagentnet.integrations import autogen as san_autogen
from secureagentnet.integrations import langchain as san_langchain
from secureagentnet.integrations import crewai as san_crewai
from tests.unit.test_integrations.test_base import FakeExecutor


class FakeRunTool:
    """Stand-in for a BaseTool-style tool (has name/description/_run, no .func)."""

    def __init__(self):
        self.name = "shell"
        self.description = "runs a shell command"
        self.ran = False

    def _run(self, cmd):
        self.ran = True
        return f"ran: {cmd}"


class FakeFuncTool:
    """Stand-in for a CrewAI @tool function tool (has .func)."""

    def __init__(self):
        self.name = "fs"
        self.description = "filesystem tool"

        def fs(path, action):
            return f"{action}:{path}"

        self.func = fs


# ── AutoGen ──────────────────────────────────────────────────────────
def test_autogen_secure_function_routes_and_preserves_name():
    ex = FakeExecutor({"status": "success", "data": {"stdout": "query ok"}})

    def db_query(sql):
        """query the db"""
        return sql

    secured = san_autogen.secure_function(db_query, target_resource="database", executor=ex)
    assert secured("SELECT 1") == "query ok"
    assert secured.__name__ == "db_query"
    assert ex.calls[0]["target_resource"] == "database"


def test_autogen_secure_function_blocked():
    ex = FakeExecutor({"status": "blocked", "reason": "exfiltration"})
    secured = san_autogen.secure_function(lambda q: q, executor=ex)
    assert secured("SELECT * FROM secrets").startswith(BLOCKED_PREFIX)


# ── LangChain (class-style _run path, no framework import) ───────────
def test_langchain_secure_tool_run_path():
    ex = FakeExecutor({"status": "success", "data": {"stdout": "ok"}})
    tool = FakeRunTool()
    secured = san_langchain.secure_tool(tool, executor=ex)
    assert secured is tool  # wrapped in place
    assert tool._run("echo hi") == "ok"
    assert tool.ran is False  # original body delegated to SAN, not run locally
    assert ex.calls[0]["target_resource"] == "shell"


def test_langchain_secure_tool_blocked_message():
    ex = FakeExecutor({"status": "blocked", "reason": "cat /etc/passwd"})
    tool = san_langchain.secure_tool(FakeRunTool(), executor=ex)
    assert tool._run("cat /etc/passwd").startswith(BLOCKED_PREFIX)


def test_langchain_secure_tool_rejects_unknown_shape():
    import pytest

    class Bare:
        name = "x"

    with pytest.raises(TypeError):
        san_langchain.secure_tool(Bare(), executor=FakeExecutor({}))


# ── CrewAI (both func and _run paths, no framework import) ───────────
def test_crewai_secure_tool_func_path():
    ex = FakeExecutor({"status": "success", "data": {"stdout": "fs ok"}})
    tool = san_crewai.secure_tool(FakeFuncTool(), executor=ex)
    assert tool.func("/tmp/x", "read") == "fs ok"
    assert ex.calls[0]["target_resource"] == "fs"


def test_crewai_secure_tool_run_path_blocked():
    ex = FakeExecutor({"status": "blocked", "reason": "denied"})
    tool = san_crewai.secure_tool(FakeRunTool(), executor=ex)
    assert tool._run("rm -rf /").startswith(BLOCKED_PREFIX)