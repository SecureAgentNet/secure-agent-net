"""A real LangChain agent guarded by SecureAgentNet.

This script imports LangChain (so SAN's discovery detects the process as a
LangChain agent) and wraps the agent's tools with `secure_tools`, so every tool
call is routed through the ITCD pipeline. It then shows the pipeline allowing a
benign action and blocking a malicious one.

Run:
    python examples/langchain_agent.py            # run the protected-tool demo
    python examples/langchain_agent.py --serve    # also stay alive so `san` discovery can find it
"""
from __future__ import annotations

import os
import sys
import time

# Real LangChain imports — also the signature SAN discovery keys off.
from langchain_core.tools import tool

from secureagentnet.identify.capability_profiler import CapabilityProfiler
from secureagentnet.identify.identity_registry import IdentityRegistry
from secureagentnet.decide.intent_capsule import MandateRegistry
from secureagentnet.integrations.langchain import secure_tools

AGENT_NAME = "langchain-research-bot"
GOAL = ("Run read-only diagnostic shell commands (echo, ls, df) to help "
        "operators triage the system. Never read secrets or private keys.")


def setup_san_agent() -> str:
    """Register + commission this LangChain agent with SecureAgentNet."""
    existing = IdentityRegistry.get_agent_by_name(AGENT_NAME)
    if existing:
        agent_id = existing["agent_id"]
    else:
        agent = IdentityRegistry.register_agent({
            "name": AGENT_NAME, "type": "LangChain", "created_by": "example",
            "capabilities": {"execute": True},
        })
        agent_id = agent["agent_id"]
    CapabilityProfiler.add_capability(agent_id, "execute")
    MandateRegistry.commission(
        agent_id=agent_id,
        original_goal=GOAL,
        approved_actions=["execute"],
        forbidden_actions=["exfiltrate_keys", "delete_database"],
        user_id="example",
        expires_in_minutes=60,
    )
    # The integration's in-process executor acts as this agent.
    os.environ["SECURE_AGENT_ID"] = agent_id
    return agent_id


@tool
def shell(command: str) -> str:
    """Run a shell command to help answer the user's question."""
    # Body never runs in-process: SecureAgentNet adjudicates and sandboxes it.
    return command


def main() -> None:
    print("=" * 64)
    print("  LangChain agent + SecureAgentNet (ITCD pipeline)")
    print("=" * 64)
    agent_id = setup_san_agent()
    print(f"Commissioned LangChain agent '{AGENT_NAME}'")
    print(f"  id:   {agent_id}")
    print(f"  goal: {GOAL}\n")

    # One line secures every tool — calls now flow through Identify→Track→Contain→Decide.
    tools = secure_tools([shell])
    run = tools[0]

    def verdict(result: str) -> str:
        if result.startswith("[SecureAgentNet] Blocked"):
            return "BLOCKED by ITCD — " + result.split(":", 1)[-1].strip()
        if result.startswith("[SecureAgentNet] Escalated"):
            return "ESCALATED to human review — " + result.split(":", 1)[-1].strip()
        return "ALLOWED by ITCD (the gate permitted this action)"

    print("[1] Benign tool call (serves the mandate — a read-only diagnostic):")
    print("    agent runs: df -h")
    print("    ->", verdict(run.invoke({"command": "df -h"})))

    print("\n[2] Malicious tool call (exfiltrate SSH keys):")
    print("    agent runs: cat /root/.ssh/id_rsa")
    print("    ->", verdict(run.invoke({"command": "cat /root/.ssh/id_rsa"})))

    print("\nThe agent's own code could not bypass the gate — the malicious call")
    print("never executed; the ITCD pipeline blocked it.")

    if "--serve" in sys.argv:
        print("\n[--serve] staying alive so `san`/the daemon can discover this agent…")
        while True:
            time.sleep(5)


if __name__ == "__main__":
    main()
