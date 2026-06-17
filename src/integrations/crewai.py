"""CrewAI adapter for SecureAgentNet.

    from src.integrations.crewai import secure_tool

    my_tool = secure_tool(my_tool)   # every CrewAI tool call goes through ITCD
"""
from typing import Any, List, Optional

from src.integrations.base import (
    SecureExecutor,
    get_default_executor,
    secure_callable,
)


def secure_tool(
    tool: Any,
    *,
    action_name: str = "execute",
    target_resource: Optional[str] = None,
    intent_summary: str = "",
    executor: Optional[SecureExecutor] = None,
) -> Any:
    """Wrap a CrewAI tool so each invocation is routed through SAN.

    Supports CrewAI ``BaseTool`` instances (``._run``) and ``@tool``-decorated
    function tools (``.func``).
    """
    ex = executor or get_default_executor()
    resource = target_resource or getattr(tool, "name", None) or "tool"
    intent = intent_summary or getattr(tool, "description", "") or ""

    func = getattr(tool, "func", None)
    if callable(func):
        try:
            object.__setattr__(
                tool, "func",
                secure_callable(func, action_name=action_name, target_resource=resource,
                                intent_summary=intent, executor=ex),
            )
        except Exception:  # pragma: no cover
            tool.func = secure_callable(func, action_name=action_name, target_resource=resource,
                                        intent_summary=intent, executor=ex)
        return tool

    run = getattr(tool, "_run", None)
    if callable(run):
        secured = secure_callable(run, action_name=action_name, target_resource=resource,
                                  intent_summary=intent, executor=ex)
        try:
            object.__setattr__(tool, "_run", secured)
        except Exception:  # pragma: no cover
            tool._run = secured
        return tool

    raise TypeError("Unsupported CrewAI tool: expected a tool with `.func` or `._run`.")


def secure_tools(tools: List[Any], **kwargs) -> List[Any]:
    """Secure a list of CrewAI tools."""
    return [secure_tool(t, **kwargs) for t in tools]