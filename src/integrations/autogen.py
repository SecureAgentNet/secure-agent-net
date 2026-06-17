"""AutoGen adapter for SecureAgentNet.

    from src.integrations.autogen import secure_function, register_secured

    safe_fn = secure_function(my_tool)                 # ITCD-governed callable
    register_secured(my_tool, caller=assistant, executor=user_proxy)
"""
from typing import Any, Callable, Optional

from src.integrations.base import (
    SecureExecutor,
    get_default_executor,
    secure_callable,
)


def secure_function(
    fn: Callable[..., Any],
    *,
    action_name: str = "execute",
    target_resource: Optional[str] = None,
    intent_summary: str = "",
    executor: Optional[SecureExecutor] = None,
) -> Callable[..., Any]:
    """Return an ITCD-governed version of an AutoGen tool function.

    The returned callable has the same name/docstring, so AutoGen's function
    registration (which reads those) keeps working.
    """
    resource = target_resource or getattr(fn, "__name__", "tool")
    return secure_callable(
        fn,
        action_name=action_name,
        target_resource=resource,
        intent_summary=intent_summary,
        executor=executor or get_default_executor(),
    )


def register_secured(
    fn: Callable[..., Any],
    *,
    caller: Any,
    executor: Any,
    name: Optional[str] = None,
    description: Optional[str] = None,
    action_name: str = "execute",
    target_resource: Optional[str] = None,
    intent_summary: str = "",
    secure_executor: Optional[SecureExecutor] = None,
) -> Callable[..., Any]:
    """Wrap ``fn`` with SAN and register it with AutoGen via ``register_function``.

    ``caller``/``executor`` are the AutoGen agents (the LLM assistant and the
    user-proxy that runs tools). ``secure_executor`` is the SAN executor.
    """
    import autogen  # noqa: F401  (clear ImportError if AutoGen is absent)

    secured = secure_function(
        fn, action_name=action_name, target_resource=target_resource,
        intent_summary=intent_summary, executor=secure_executor,
    )
    autogen.register_function(
        secured,
        caller=caller,
        executor=executor,
        name=name or getattr(fn, "__name__", "tool"),
        description=description or (getattr(fn, "__doc__", "") or "").strip(),
    )
    return secured