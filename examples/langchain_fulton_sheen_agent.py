"""LangChain filesystem research agent protected by SecureAgentNet.

The underlying tool is intentionally a real subprocess-based search.  The
SecureAgentNet LangChain wrapper is the enforcement point before it executes.
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
from typing import Any

from langchain_core.tools import StructuredTool

from secureagentnet.integrations.wrappers.langchain import SecureAgentNetLangChainTool


def _search_files(root: str = "/home", max_results: int = 100, intent: str = "", command: str = "") -> str:
    """Search readable files for Fulton Sheen, returning JSON records."""
    # ripgrep performs the traversal directly and avoids spawning one process
    # per file (which can time out on a home directory containing caches).
    command = (
        f"rg -i -l --hidden --no-messages "
        f"--glob '!proc/**' --glob '!sys/**' --glob '!dev/**' "
        f"--glob '!run/**' --glob '!**/.cache/**' --glob '!**/node_modules/**' "
        f"--glob '!**/.git/**' --glob '!**/venv/**' "
        f"'Fulton[[:space:]]+Sheen' {shlex.quote(root)} | head -n {int(max_results)}"
    )
    completed = subprocess.run(command, shell=True, text=True, capture_output=True, timeout=60)
    if completed.returncode not in (0, 1):
        raise RuntimeError(completed.stderr.strip() or f"search failed ({completed.returncode})")
    paths = [line for line in completed.stdout.splitlines() if line]
    return json.dumps({"query": "Fulton Sheen", "root": root, "matches": paths}, indent=2)


raw_tool = StructuredTool.from_function(
    func=_search_files,
    name="search_fulton_sheen_files",
    description="Search readable files below a root for the exact name Fulton Sheen.",
)


def build_agent_tool(agent_id: str) -> SecureAgentNetLangChainTool:
    return SecureAgentNetLangChainTool(
        agent_id=agent_id,
        tool=raw_tool,
        target_resource="local-filesystem",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent-id", default=os.environ.get("SECURE_AGENT_ID"), required=False)
    parser.add_argument("--root", default="/home", help="Search root; use / for the full system-wide test")
    parser.add_argument("--max-results", type=int, default=100)
    args = parser.parse_args()
    if not args.agent_id:
        parser.error("--agent-id or SECURE_AGENT_ID is required")

    tool = build_agent_tool(args.agent_id)
    result = tool.invoke({
        "root": args.root,
        "max_results": args.max_results,
        "intent": "Locate files written by Fulton Sheen for the commissioned research task",
        "command": "search_fulton_sheen_files",
    })
    print(result)


if __name__ == "__main__":
    main()
