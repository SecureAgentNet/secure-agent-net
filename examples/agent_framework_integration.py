"""Securing existing agent tools with SecureAgentNet — one line per framework.

Every tool call is routed through the ITCD pipeline (Identify → Track → Contain →
Decide). Approved calls return their result; blocked calls return a policy message
the agent can read and react to.

This script is self-contained: it uses a small in-script `DemoExecutor` and mock
tool objects so it runs anywhere, with no gateway, database, or framework install.
In a real deployment you swap `DemoExecutor()` for one of:

    from secureagentnet.integrations import LocalExecutor   # in-process ITCD pipeline
    executor = LocalExecutor(agent_id="my-agent")

    from secureagentnet.integrations import RemoteExecutor  # remote SAN gateway
    executor = RemoteExecutor(gateway_url="http://localhost:5000",
                              agent_id="my-agent", private_key_pem=KEY)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from secureagentnet.integrations.langchain import secure_tool as secure_langchain_tool
from secureagentnet.integrations.crewai import secure_tool as secure_crewai_tool
from secureagentnet.integrations.autogen import secure_function


# ── A stand-in executor so the demo runs with no infrastructure ──────────────
class DemoExecutor:
    """Illustrative SecureExecutor: blocks obviously dangerous commands, allows
    the rest. Real deployments use LocalExecutor or RemoteExecutor instead."""

    DANGER = ("rm -rf", "/etc/passwd", "/etc/shadow", "exfil", "drop table", "curl ")

    def execute(self, *, action_name, target_resource, command, intent_summary, payload):
        if any(d in command.lower() for d in self.DANGER):
            return {"status": "blocked", "reason": f"dangerous pattern in '{command}'"}
        return {"status": "success", "data": {"stdout": f"executed: {command}", "stderr": ""}}


# ── Mock framework tools (so no framework install is needed to run the demo) ──
class LangChainShellTool:
    """Mimics a LangChain BaseTool (name/description/_run)."""
    name = "shell"
    description = "Execute a shell command"

    def _run(self, command):
        return f"(would run locally) {command}"


class CrewAIFileTool:
    """Mimics a CrewAI @tool function tool (.func)."""
    name = "filesystem"
    description = "Read or write files in the workspace"

    def __init__(self):
        def fs(path, action):
            return f"(would {action}) {path}"
        self.func = fs


def autogen_db_query(sql: str) -> str:
    """AutoGen tool: run a database query."""
    return f"(would query) {sql}"


def banner(title):
    print("\n" + title)
    print("-" * 56)


def main():
    print("=" * 56)
    print("  SecureAgentNet — framework integration (demo)")
    print("=" * 56)
    executor = DemoExecutor()

    # One line each: wrap the framework's tool so calls flow through ITCD.
    lc_tool = secure_langchain_tool(LangChainShellTool(), executor=executor)
    crew_tool = secure_crewai_tool(CrewAIFileTool(), executor=executor)
    ag_query = secure_function(autogen_db_query, target_resource="database", executor=executor)

    banner("LangChain tool")
    print("safe   :", lc_tool._run("echo 'stats compiled'"))
    print("attack :", lc_tool._run("cat /etc/passwd"))

    banner("CrewAI tool")
    print("safe   :", crew_tool.func("report.txt", "read"))
    print("attack :", crew_tool.func("rm -rf /", "delete"))

    banner("AutoGen tool")
    print("safe   :", ag_query("SELECT count(*) FROM sales"))
    print("attack :", ag_query("DROP TABLE users"))

    print("\n" + "=" * 56)
    print("  Blocked calls never reached the tool body — ITCD denied them.")
    print("=" * 56)


if __name__ == "__main__":
    main()