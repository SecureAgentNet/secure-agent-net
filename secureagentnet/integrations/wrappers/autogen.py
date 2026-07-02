"""AutoGen tool wrapper that routes function calls through SecureAgentNet."""
from __future__ import annotations

import functools
from typing import Any, Callable, Optional

from secureagentnet.integrations.wrappers.client import InterceptClient


try:
    from autogen import ConversableAgent
except ImportError as exc:
    raise ImportError(
        "AutoGen is required for SecureAgentNetAutoGenTool. "
        "Install it with: pip install pyautogen"
    ) from exc


def secureagentnet_autogen_tool(
    agent_id: str,
    name: Optional[str] = None,
    target_resource: str = "tool",
    client: Optional[InterceptClient] = None,
) -> Callable:
    """Decorator that wraps an AutoGen-registered function with the SecureAgentNet daemon.

    Example:
        @secureagentnet_autogen_tool(agent_id="my-agent", name="read_file")
        def read_file(path: str) -> str:
            return Path(path).read_text()
    """
    def decorator(func: Callable) -> Callable:
        tool_name = name or func.__name__
        intercept_client = client or InterceptClient()

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            result = intercept_client.intercept(
                agent_id=agent_id,
                action_name=tool_name,
                target_resource=target_resource,
                intent_summary=kwargs.get("intent", f"Run {tool_name}"),
                payload=kwargs,
            )
            if result.get("status") == "blocked":
                return f"[BLOCKED by SecureAgentNet] {result.get('reason', 'blocked')}"
            if result.get("status") == "error":
                return f"[ERROR] {result.get('reason', 'unknown error')}"
            return func(*args, **kwargs)

        return wrapper

    return decorator
