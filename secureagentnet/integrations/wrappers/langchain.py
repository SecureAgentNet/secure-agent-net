"""LangChain tool wrapper that routes tool calls through SecureAgentNet."""
from __future__ import annotations

from typing import Any, Optional

from secureagentnet.integrations.wrappers.client import InterceptClient


try:
    from langchain.tools import BaseTool
except ImportError as exc:
    raise ImportError(
        "LangChain is required for SecureAgentNetLangChainTool. "
        "Install it with: pip install langchain"
    ) from exc


class SecureAgentNetLangChainTool(BaseTool):
    """Wraps an existing LangChain tool so every call is evaluated by the daemon.

    The wrapper preserves the original tool's name, description, and args_schema.
    """

    name: str
    description: str
    agent_id: str
    wrapped_tool: BaseTool
    target_resource: str = "tool"
    client: InterceptClient

    def __init__(
        self,
        agent_id: str,
        tool: BaseTool,
        target_resource: str = "tool",
        client: Optional[InterceptClient] = None,
        **kwargs: Any,
    ):
        # Copy metadata from wrapped tool.
        kwargs.setdefault("name", tool.name)
        kwargs.setdefault("description", tool.description)
        if hasattr(tool, "args_schema"):
            kwargs.setdefault("args_schema", tool.args_schema)
        super().__init__(**kwargs)
        self.agent_id = agent_id
        self.wrapped_tool = tool
        self.target_resource = target_resource
        self.client = client or InterceptClient()

    def _run(self, *args: Any, **kwargs: Any) -> str:
        intent = kwargs.get("intent", f"Run {self.name}")
        command = kwargs.get("command")

        result = self.client.intercept(
            agent_id=self.agent_id,
            action_name=self.name,
            target_resource=self.target_resource,
            intent_summary=intent,
            payload=kwargs,
            command=command,
        )

        if result.get("status") == "blocked":
            reason = result.get("reason", "blocked by security policy")
            return f"[BLOCKED by SecureAgentNet] {reason}"

        if result.get("status") == "error":
            return f"[ERROR] {result.get('reason', 'unknown error')}"

        # Allowed: execute the underlying tool.
        try:
            return self.wrapped_tool._run(*args, **kwargs)
        except Exception as exc:
            return f"[ERROR] underlying tool failed: {exc}"

    async def _arun(self, *args: Any, **kwargs: Any) -> str:
        return self._run(*args, **kwargs)
