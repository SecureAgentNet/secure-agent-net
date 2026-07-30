"""LangChain adapter for SecureAgentNet.

    from secureagentnet.integrations.langchain import secure_tool, secure_tools

    tools = secure_tools(my_tools)          # one line — every call goes through ITCD
    agent = create_react_agent(llm, tools)
"""
from typing import Any, Callable, List, Optional

from secureagentnet.integrations.base import (
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
    enforce_only: bool = False,
    target_resolver: Optional[Callable[[tuple, dict], str]] = None,
) -> Any:
    """Wrap a single LangChain tool so each invocation is routed through SAN.

    Works with both function tools (``StructuredTool`` / ``@tool`` — they expose
    ``.func``) and class tools (``BaseTool`` subclasses — they expose ``._run``).

    ``enforce_only=True`` adjudicates the call and, on approval, runs the tool's
    real body in-process (for tools with a genuine side effect like sending an
    email — see ``secure_callable``). ``target_resolver(args, kwargs)`` derives
    the DECIDE target from the call's arguments (e.g. the email recipient).
    """
    ex = executor or get_default_executor()
    resource = target_resource or getattr(tool, "name", None) or "tool"
    intent = intent_summary or getattr(tool, "description", "") or ""
    kw = dict(action_name=action_name, target_resource=resource, intent_summary=intent,
              executor=ex, enforce_only=enforce_only, target_resolver=target_resolver)

    # Function-style tool: rebuild it from a secured copy of its callable.
    func = getattr(tool, "func", None)
    if callable(func):
        secured = secure_callable(func, **kw)
        from langchain_core.tools import StructuredTool

        return StructuredTool.from_function(
            func=secured,
            name=getattr(tool, "name", secured.__name__),
            description=getattr(tool, "description", "") or "",
            args_schema=getattr(tool, "args_schema", None),
        )

    # Class-style tool: replace its private runner in place (bypass pydantic guards).
    run = getattr(tool, "_run", None)
    if callable(run):
        secured = secure_callable(run, **kw)
        try:
            object.__setattr__(tool, "_run", secured)
        except Exception:  # pragma: no cover - extremely defensive
            tool._run = secured
        return tool

    raise TypeError(
        "Unsupported LangChain tool: expected a tool with `.func` or `._run`."
    )


def secure_tools(tools: List[Any], **kwargs) -> List[Any]:
    """Secure a list of LangChain tools. Extra kwargs are passed to ``secure_tool``."""
    return [secure_tool(t, **kwargs) for t in tools]


class SecureAgentNetCallbackHandler:
    """Optional callback handler that records when tool calls pass through SAN.

    Intended to be added to a LangChain run's callbacks for observability; the
    actual enforcement happens in the wrapped tools (``secure_tool``).
    """

    def __init__(self, executor: Optional[SecureExecutor] = None):
        self.executor = executor or get_default_executor()

    def on_tool_start(self, serialized, input_str, **kwargs):  # pragma: no cover
        name = (serialized or {}).get("name", "tool")
        import logging

        logging.getLogger("SecureAgentNet.Integrations").info(
            "LangChain tool '%s' invoked (input=%r)", name, input_str
        )
