"""LangChain tool wrapper that routes tool calls through SecureAgentNet."""
from __future__ import annotations

from typing import Any, Optional

from secureagentnet.integrations.wrappers.client import InterceptClient, format_denial, is_allowed


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
        # These are Pydantic model fields on BaseTool.  They must be supplied
        # to BaseTool's constructor (rather than assigned after super()),
        # otherwise LangChain 1.x/Pydantic v2 reports them as missing.
        kwargs.setdefault("agent_id", agent_id)
        kwargs.setdefault("wrapped_tool", tool)
        kwargs.setdefault("target_resource", target_resource)
        kwargs.setdefault("client", client or InterceptClient())
        super().__init__(**kwargs)

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

        # Default-deny: run the real tool only on an explicit approval.
        if not is_allowed(result):
            return format_denial(result)

        # Allowed: execute the underlying tool.
        try:
            # Use LangChain's public execution API. StructuredTool._run is an
            # internal method whose signature now requires a keyword-only
            # RunnableConfig in LangChain 1.x.
            tool_input: Any
            if kwargs:
                tool_input = dict(kwargs)
                # Wrapper-only context is evaluated by SAN but is not part of
                # the underlying tool's declared input schema.
                tool_input.pop("intent", None)
                tool_input.pop("command", None)
            elif len(args) == 1:
                tool_input = args[0]
            else:
                tool_input = args
            return self.wrapped_tool.invoke(tool_input)
        except Exception as exc:
            return f"[ERROR] underlying tool failed: {exc}"

    async def _arun(self, *args: Any, **kwargs: Any) -> str:
        return self._run(*args, **kwargs)
