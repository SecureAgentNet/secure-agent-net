"""CrewAI tool wrapper that routes tool calls through SecureAgentNet."""
from __future__ import annotations

from typing import Any, Callable, Optional

from secureagentnet.integrations.wrappers.client import InterceptClient, format_denial, is_allowed


try:
    from crewai.tools import BaseTool as CrewAIBaseTool
except ImportError:
    # CrewAI versions differ in their import paths. Try the older path as fallback.
    try:
        from crewai import Tool as CrewAIBaseTool
    except ImportError as exc:
        raise ImportError(
            "CrewAI is required for SecureAgentNetCrewAITool. "
            "Install it with: pip install crewai"
        ) from exc


class SecureAgentNetCrewAITool(CrewAIBaseTool):
    """Wraps a CrewAI tool so every invocation is routed through the daemon."""

    name: str
    description: str
    agent_id: str
    wrapped_callable: Callable
    target_resource: str = "tool"
    client: InterceptClient

    def __init__(
        self,
        agent_id: str,
        name: str,
        description: str,
        func: Callable,
        target_resource: str = "tool",
        client: Optional[InterceptClient] = None,
        **kwargs: Any,
    ):
        super().__init__(name=name, description=description, func=func, **kwargs)
        self.agent_id = agent_id
        self.wrapped_callable = func
        self.target_resource = target_resource
        self.client = client or InterceptClient()

    def _run(self, *args: Any, **kwargs: Any) -> str:
        intent = kwargs.get("intent", f"Run {self.name}")
        result = self.client.intercept(
            agent_id=self.agent_id,
            action_name=self.name,
            target_resource=self.target_resource,
            intent_summary=intent,
            payload=kwargs,
        )

        # Default-deny: run the real tool only on an explicit approval.
        if not is_allowed(result):
            return format_denial(result)

        try:
            return str(self.wrapped_callable(*args, **kwargs))
        except Exception as exc:
            return f"[ERROR] underlying tool failed: {exc}"
