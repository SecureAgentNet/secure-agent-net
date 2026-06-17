"""Shared core for SecureAgentNet framework adapters.

A framework "tool" is wrapped so that invoking it routes the call through the
full ITCD pipeline (Identify → Track → Contain → Decide) instead of executing in
the agent's trusted process. On approval the result is returned; on a block or a
human-in-the-loop escalation a message string is returned so the agent can adapt.
"""
import asyncio
import concurrent.futures
import logging
import os
from typing import Any, Callable, Dict, Optional, Protocol, runtime_checkable

logger = logging.getLogger("SecureAgentNet.Integrations")

BLOCKED_PREFIX = "[SecureAgentNet] Blocked by policy"
ESCALATED_PREFIX = "[SecureAgentNet] Escalated to human review"


@runtime_checkable
class SecureExecutor(Protocol):
    """Routes a single tool invocation through SAN and returns the raw result dict."""

    def execute(
        self,
        *,
        action_name: str,
        target_resource: str,
        command: str,
        intent_summary: str,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        ...


class LocalExecutor:
    """Runs the ITCD pipeline in-process — no gateway server required."""

    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        from src.core.pipeline import ITCDPipeline

        self._pipeline = ITCDPipeline()

    def execute(self, *, action_name, target_resource, command, intent_summary, payload):
        from src.track.models import AgentActionRequest

        request = AgentActionRequest(
            action_name=action_name,
            target_resource=target_resource,
            intent_summary=intent_summary,
            payload=payload or {},
        )
        return _run_coro(
            self._pipeline.execute_agent_action(self.agent_id, request, command)
        )


class RemoteExecutor:
    """Routes a call to a remote SAN gateway over HTTP via the client SDK."""

    def __init__(
        self,
        client: Any = None,
        *,
        gateway_url: Optional[str] = None,
        agent_id: Optional[str] = None,
        private_key_pem: Optional[str] = None,
    ):
        if client is None:
            from src.client import SecureAgentClient

            client = SecureAgentClient(
                gateway_url=gateway_url,
                agent_id=agent_id,
                private_key_pem=private_key_pem,
            )
        self._client = client

    def execute(self, *, action_name, target_resource, command, intent_summary, payload):
        return self._client.execute_tool(
            action_name=action_name,
            target_resource=target_resource,
            command=command,
            intent_summary=intent_summary,
            payload=payload or {},
        )


def get_default_executor() -> SecureExecutor:
    """Pick an executor from the environment.

    ``SECURE_GATEWAY_URL`` → remote gateway; otherwise an in-process pipeline
    using ``SECURE_AGENT_ID`` (default ``agent-007``).
    """
    if os.environ.get("SECURE_GATEWAY_URL"):
        from src.client import SecureRuntimeWrapper

        return RemoteExecutor(client=SecureRuntimeWrapper().client)
    return LocalExecutor(agent_id=os.environ.get("SECURE_AGENT_ID", "agent-007"))


def _run_coro(coro):
    """Run a coroutine from sync code, even when an event loop is already running
    (e.g. inside an async agent) by offloading to a worker thread."""
    try:
        running = asyncio.get_running_loop()
    except RuntimeError:
        running = None
    if running is not None:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            return ex.submit(lambda: asyncio.run(coro)).result()
    return asyncio.run(coro)


def format_command(args: tuple, kwargs: dict) -> str:
    """Render positional/keyword tool arguments into a single command string."""
    parts = [str(a) for a in args]
    parts += [f"--{k}={v}" for k, v in kwargs.items()]
    return " ".join(parts)


def interpret_result(res: Dict[str, Any]) -> str:
    """Turn a pipeline/gateway result dict into a string the agent can read."""
    status = res.get("status")
    if status == "blocked":
        reason = res.get("reason") or res.get("stderr") or "policy denial"
        return f"{BLOCKED_PREFIX}: {reason}"
    if status == "escalated":
        reason = res.get("reason") or "pending approval"
        return f"{ESCALATED_PREFIX}: {reason}"
    data = res.get("data")
    if isinstance(data, dict):
        return data.get("stdout") or data.get("stderr") or ""
    return res.get("stdout") or res.get("stderr") or ""


def secure_callable(
    fn: Callable[..., Any],
    *,
    action_name: str = "execute",
    target_resource: str = "tool",
    intent_summary: str = "",
    executor: Optional[SecureExecutor] = None,
) -> Callable[..., Any]:
    """Wrap any callable so its invocation is governed by the SAN ITCD pipeline.

    The wrapped call is delegated to SAN (which adjudicates and sandboxes it); the
    original function body is not run in-process. Returns the sandbox output on
    approval, or a ``[SecureAgentNet] Blocked…/Escalated…`` message otherwise.
    """
    ex = executor or get_default_executor()
    name = getattr(fn, "__name__", "tool")
    intent = intent_summary or f"Agent invoking tool: {name}"

    def wrapper(*args, **kwargs):
        command = format_command(args, kwargs) or name
        logger.info("Routing tool '%s' through SecureAgentNet…", name)
        res = ex.execute(
            action_name=action_name,
            target_resource=target_resource,
            command=command,
            intent_summary=intent,
            payload={"args": list(args), "kwargs": dict(kwargs)},
        )
        return interpret_result(res)

    wrapper.__name__ = name
    wrapper.__doc__ = getattr(fn, "__doc__", None)
    wrapper.__wrapped__ = fn
    return wrapper


def require_package(import_name: str, pip_name: str):
    """Import a framework package or raise a helpful install hint."""
    try:
        return __import__(import_name)
    except ImportError as e:  # pragma: no cover - exercised only when missing
        raise ImportError(
            f"This adapter requires '{pip_name}'. Install it with: pip install {pip_name}"
        ) from e