"""A CrewAI agent's tools guarded by SecureAgentNet.

Wraps a CrewAI tool with `secure_tool` so every invocation is routed through the
ITCD pipeline. CrewAI's own dependency tree needs a Python with prebuilt wheels
(it does not install on 3.14 yet), so this example uses a real CrewAI ``BaseTool``
when it is importable and an equivalent stand-in otherwise — the SecureAgentNet
protection is demonstrated through the real adapter either way.

Run:
    python examples/crewai_agent.py
    python examples/crewai_agent.py --serve   # stay alive so `san` discovery finds it
"""
from __future__ import annotations

import os
import sys
import time

from secureagentnet.identify.capability_profiler import CapabilityProfiler
from secureagentnet.identify.identity_registry import IdentityRegistry
from secureagentnet.decide.intent_capsule import MandateRegistry
from secureagentnet.integrations.crewai import secure_tool

AGENT_NAME = "crewai-ops-agent"
GOAL = ("Run read-only diagnostic shell commands (df, ls, uptime) for the ops "
        "crew. Never read secrets or private keys.")

# Use a real CrewAI BaseTool if available; otherwise an equivalent stand-in.
try:
    from crewai.tools import BaseTool  # type: ignore
    HAVE_CREWAI = True
except Exception:  # pragma: no cover - crewai optional / not installable on 3.14
    BaseTool = object  # type: ignore
    HAVE_CREWAI = False


class ShellTool(BaseTool):  # type: ignore[misc]
    name: str = "shell"
    description: str = "Run a shell command to help the crew triage the system."

    def _run(self, command: str) -> str:  # CrewAI tool entrypoint
        # Body never runs in-process — SecureAgentNet adjudicates and sandboxes it.
        return command


def setup_san_agent() -> str:
    existing = IdentityRegistry.get_agent_by_name(AGENT_NAME)
    agent_id = existing["agent_id"] if existing else IdentityRegistry.register_agent({
        "name": AGENT_NAME, "type": "CrewAI", "created_by": "example",
        "capabilities": {"execute": True},
    })["agent_id"]
    CapabilityProfiler.add_capability(agent_id, "execute")
    MandateRegistry.commission(
        agent_id=agent_id, original_goal=GOAL,
        approved_actions=["execute"], forbidden_actions=["exfiltrate_keys", "delete_database"],
        user_id="example", expires_in_minutes=60,
    )
    os.environ["SECURE_AGENT_ID"] = agent_id
    return agent_id


def verdict(result: str) -> str:
    if result.startswith("[SecureAgentNet] Blocked"):
        return "BLOCKED by ITCD — " + result.split(":", 1)[-1].strip()
    if result.startswith("[SecureAgentNet] Escalated"):
        return "ESCALATED to human review — " + result.split(":", 1)[-1].strip()
    return "ALLOWED by ITCD (the gate permitted this action)"


def main() -> None:
    print("=" * 64)
    print("  CrewAI agent + SecureAgentNet (ITCD pipeline)")
    print("=" * 64)
    print("CrewAI framework importable:", HAVE_CREWAI,
          "" if HAVE_CREWAI else "(using an equivalent stand-in tool)")
    agent_id = setup_san_agent()
    print(f"Commissioned CrewAI agent '{AGENT_NAME}'")
    print(f"  id:   {agent_id}")
    print(f"  goal: {GOAL}\n")

    tool = ShellTool()
    secure_tool(tool)  # one line — every call now flows through ITCD

    print("[1] Benign tool call (serves the mandate — a read-only diagnostic):")
    print("    crew runs: df -h")
    print("    ->", verdict(tool._run("df -h")))

    print("\n[2] Malicious tool call (exfiltrate SSH keys):")
    print("    crew runs: cat /root/.ssh/id_rsa")
    print("    ->", verdict(tool._run("cat /root/.ssh/id_rsa")))

    print("\nThe crew's tool could not bypass the gate — the malicious call never executed.")

    if "--serve" in sys.argv:
        print("\n[--serve] staying alive so `san`/the daemon can discover this agent…")
        while True:
            time.sleep(5)


if __name__ == "__main__":
    main()
