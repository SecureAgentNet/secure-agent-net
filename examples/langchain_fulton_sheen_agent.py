"""LangChain filesystem research agent protected by SecureAgentNet.

The underlying tool is intentionally a real subprocess-based search over the
local filesystem. The SecureAgentNet LangChain wrapper is the enforcement point
before it executes: every call is adjudicated by the ITCD pipeline first, and the
search only runs on approval.

The search term is a parameter, so one commissioned agent can be pointed at any
name or phrase. That also makes the mandate meaningful — the phrase travels in
the intent and payload, so DECIDE can judge *what is being searched for* against
the goal the agent was commissioned with, not merely that a search happened.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import time
from typing import Any, List

from langchain_core.tools import StructuredTool

from secureagentnet.integrations.wrappers.langchain import SecureAgentNetLangChainTool


# Directories that are either not real files or are pure noise for a name search.
_SKIP_GLOBS = (
    "!proc/**", "!sys/**", "!dev/**", "!run/**",
    "!**/.cache/**", "!**/node_modules/**", "!**/.git/**", "!**/venv/**",
)

_SEARCH_TIMEOUT_SECONDS = 60


def _phrase_pattern(term: str) -> str:
    """Build a regex matching ``term`` with flexible whitespace between words.

    Every word is regex-escaped, so a phrase containing metacharacters ("C++",
    "St. John (Jr.)") is matched literally rather than being interpreted — and
    cannot smuggle a pattern that makes ripgrep scan something unintended.
    """
    words = term.split()
    if not words:
        raise ValueError("search term is empty")
    return r"\s+".join(re.escape(word) for word in words)


def _search_files(
    term: str,
    root: str = "/home",
    max_results: int = 100,
    intent: str = "",
    command: str = "",
) -> str:
    """Search readable files below ``root`` for a name or phrase, as JSON."""
    pattern = _phrase_pattern(term)
    limit = max(1, int(max_results))

    # No shell. The term is caller-supplied, and interpolating it into a shell
    # string — even inside quotes — is injectable via a single quote. Passing an
    # argv list hands ripgrep the pattern directly, with no shell to parse it.
    argv: List[str] = ["rg", "-i", "-l", "--hidden", "--no-messages"]
    for glob in _SKIP_GLOBS:
        argv += ["--glob", glob]
    argv += ["-e", pattern, "--", root]

    # Read incrementally and stop at the limit rather than letting a search
    # rooted at "/" traverse the whole filesystem after the answer is already in
    # hand. `| head -n` did this before; the pipe went away with the shell.
    deadline = time.monotonic() + _SEARCH_TIMEOUT_SECONDS
    paths: List[str] = []
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    truncated = False
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            line = line.strip()
            if line:
                paths.append(line)
            if len(paths) >= limit or time.monotonic() > deadline:
                truncated = True
                break
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        stderr = proc.stderr.read() if proc.stderr else ""
        for stream in (proc.stdout, proc.stderr):
            if stream is not None:
                stream.close()

    # rg exits 1 when it simply found nothing; anything else is a real failure.
    # A terminate() of our own is not an error.
    if not truncated and proc.returncode not in (0, 1, None):
        raise RuntimeError(stderr.strip() or f"search failed ({proc.returncode})")

    return json.dumps(
        {"query": term, "root": root, "matches": paths, "truncated": truncated},
        indent=2,
    )


raw_tool = StructuredTool.from_function(
    func=_search_files,
    name="search_files",
    description=(
        "Search readable files below a root directory for a name or phrase. "
        "Takes the phrase to look for, the directory to search, and a result limit. "
        "Returns the matching file paths as JSON."
    ),
)


def build_agent_tool(agent_id: str) -> SecureAgentNetLangChainTool:
    return SecureAgentNetLangChainTool(
        agent_id=agent_id,
        tool=raw_tool,
        target_resource="local-filesystem",
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Search the filesystem for a name or phrase, governed by SecureAgentNet.")
    parser.add_argument("--agent-id", default=os.environ.get("SECURE_AGENT_ID"), required=False)
    parser.add_argument("--term", required=True,
                        help='Name or phrase to search for, e.g. --term "Fulton Sheen"')
    parser.add_argument("--root", default="/home", help="Search root; use / for the full system-wide test")
    parser.add_argument("--max-results", type=int, default=100)
    args = parser.parse_args()
    if not args.agent_id:
        parser.error("--agent-id or SECURE_AGENT_ID is required")

    tool = build_agent_tool(args.agent_id)
    result = tool.invoke({
        "term": args.term,
        "root": args.root,
        "max_results": args.max_results,
        # The phrase is named in the intent as well as the payload so DECIDE can
        # weigh what is being searched for against the commissioned goal.
        "intent": f"Locate files mentioning '{args.term}' for the commissioned research task",
        "command": "search_files",
    })
    print(result)


if __name__ == "__main__":
    main()
