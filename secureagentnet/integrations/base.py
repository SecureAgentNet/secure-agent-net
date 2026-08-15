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
        from secureagentnet.core.pipeline import ITCDPipeline

        self._pipeline = ITCDPipeline()

    def execute(self, *, action_name, target_resource, command, intent_summary, payload):
        from secureagentnet.track.models import AgentActionRequest

        request = AgentActionRequest(
            action_name=action_name,
            target_resource=target_resource,
            intent_summary=intent_summary,
            payload=payload or {},
        )
        return _run_coro(
            self._pipeline.execute_agent_action(self.agent_id, request, command)
        )

    def adjudicate(self, *, action_name, target_resource, intent_summary, payload):
        """Decision-only enforcement for tools with a **real in-process side effect**
        (send an email, write a row, call an API) — where sandbox-executing a shell
        ``command`` makes no sense. Runs the mandate gate (IDENTIFY) and the
        mandate-anchored DECIDE gateway, but performs no CONTAIN/execution; the
        caller runs the real tool body itself on an ``allowed`` verdict.

        Returns a status dict: ``{"status": "allowed"|"blocked"|"escalated", ...}``.
        Fail-closed: an uncommissioned/expired agent, or an action outside its
        mandate, is blocked before the request ever reaches the model tier.
        """
        from secureagentnet.decide.models import EvaluationRequest
        from secureagentnet.decide.intent_capsule import MandateRegistry

        mandate = MandateRegistry.get_active(self.agent_id)
        if mandate is None:
            return {"status": "blocked", "evaluated_by": "MandateRegistry",
                    "reason": "Agent has no active mandate — it has not been commissioned"}
        if mandate.is_expired():
            return {"status": "blocked", "evaluated_by": "MandateRegistry",
                    "reason": "Agent mandate has expired — re-commission required"}
        if mandate.detect_goal_hijack(action_name, intent_summary):
            return {"status": "blocked", "evaluated_by": "MandateRegistry",
                    "reason": f"Goal hijacking: action '{action_name}' deviates from the mandate"}
        if not mandate.is_action_allowed(action_name):
            return {"status": "blocked", "evaluated_by": "MandateRegistry",
                    "reason": f"Action '{action_name}' is outside the agent's commissioned mandate"}

        req = EvaluationRequest(
            agent_id=self.agent_id,
            action_name=action_name,
            target_resource=target_resource,
            intent_summary=intent_summary,
            payload=payload or {},
            commissioned_goal=mandate.original_goal,
        )
        result = self._pipeline.gateway.evaluate_request(req)
        hitl = bool(result.metadata.get("hitl_required")) or \
            result.evaluated_by == "HITLApprovalGate"
        status = "allowed" if result.is_allowed else ("escalated" if hitl else "blocked")
        return {"status": status, "reason": result.reason,
                "risk_score": result.risk_score, "evaluated_by": result.evaluated_by}


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
            from secureagentnet.client import SecureAgentClient

            if not (gateway_url and agent_id and private_key_pem):
                raise ValueError(
                    "RemoteExecutor requires gateway_url, agent_id and "
                    "private_key_pem when no client is supplied.")
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

    def adjudicate(self, *, action_name, target_resource, intent_summary, payload):
        """Decision-only enforcement via the **MCP gateway** (`/api/v1/mcp/execute`).

        The gateway authenticates the agent, runs the full ITCD pipeline and returns
        a verdict. For tools with a real local side effect (send an email, write a
        record) we act on the verdict and perform the effect ourselves on approval —
        the gateway's sandbox executes command *workloads*, not side effects. Any
        gateway/transport error is treated as a denial (fail-closed).
        """
        command = payload.get("command") if isinstance(payload, dict) else None
        res = self._client.execute_tool(
            action_name=action_name,
            target_resource=target_resource,
            command=command or action_name,
            intent_summary=intent_summary,
            payload=payload or {},
        )
        status = res.get("status")
        if status == "success":
            return {"status": "allowed", "reason": "approved by MCP gateway",
                    "evaluated_by": res.get("evaluated_by", "MCP gateway")}
        if status == "escalated":
            return {"status": "escalated", "reason": res.get("reason", "pending approval"),
                    "evaluated_by": res.get("evaluated_by", "MCP gateway")}
        if status == "blocked":
            return {"status": "blocked", "reason": res.get("reason", "policy denial"),
                    "evaluated_by": res.get("evaluated_by", "MCP gateway")}
        # error / unknown → fail-closed
        return {"status": "blocked",
                "reason": res.get("error") or res.get("reason") or "gateway error (fail-closed)",
                "evaluated_by": "MCP gateway"}


def get_default_executor() -> SecureExecutor:
    """Pick an executor from the environment.

    ``SECURE_GATEWAY_URL`` → remote gateway; otherwise an in-process pipeline
    using ``SECURE_AGENT_ID`` (default ``agent-007``).
    """
    if os.environ.get("SECURE_GATEWAY_URL"):
        from secureagentnet.client import SecureRuntimeWrapper

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
    enforce_only: bool = False,
    target_resolver: Optional[Callable[[tuple, dict], str]] = None,
) -> Callable[..., Any]:
    """Wrap any callable so its invocation is governed by the SAN ITCD pipeline.

    Two enforcement modes:

    * **Sandbox mode (default).** The call is delegated to SAN, which adjudicates
      *and* executes it in an isolated sandbox; the original body is not run in
      this process. Right for tools whose effect is a shell/command workload.
    * **Adjudicate-only mode** (``enforce_only=True``). SAN *decides* (mandate +
      DECIDE), and on approval the original ``fn`` runs in-process to perform its
      real side effect (send an email, write a record, call an API). Right for
      tools that must act locally, where sandboxing a synthetic command is wrong.

    ``target_resolver(args, kwargs) -> str`` optionally derives the DECIDE
    ``target_resource`` from the runtime arguments (e.g. an email's recipient), so
    the evaluator judges *this* call's target — central to catching, say, a reply
    being redirected to an external address. Returns the tool output on approval,
    or a ``[SecureAgentNet] Blocked…/Escalated…`` message otherwise.
    """
    ex = executor or get_default_executor()
    name = getattr(fn, "__name__", "tool")
    intent = intent_summary or f"Agent invoking tool: {name}"

    def _resource(args, kwargs) -> str:
        if target_resolver is not None:
            try:
                return str(target_resolver(args, kwargs)) or target_resource
            except Exception:  # noqa: BLE001 — a resolver hiccup must not bypass the gate
                return target_resource
        return target_resource

    def wrapper(*args, **kwargs):
        resource = _resource(args, kwargs)
        payload = {"args": list(args), "kwargs": dict(kwargs)}

        if enforce_only and hasattr(ex, "adjudicate"):
            logger.info("Adjudicating tool '%s' through SecureAgentNet…", name)
            decision = ex.adjudicate(
                action_name=action_name,
                target_resource=resource,
                intent_summary=intent,
                payload=payload,
            )
            status = decision.get("status")
            if status == "allowed":
                return fn(*args, **kwargs)  # approved → the real side effect runs here
            if status == "escalated":
                return f"{ESCALATED_PREFIX}: {decision.get('reason', 'pending approval')}"
            return f"{BLOCKED_PREFIX}: {decision.get('reason', 'policy denial')}"

        command = format_command(args, kwargs) or name
        logger.info("Routing tool '%s' through SecureAgentNet…", name)
        res = ex.execute(
            action_name=action_name,
            target_resource=resource,
            command=command,
            intent_summary=intent,
            payload=payload,
        )
        return interpret_result(res)

    wrapper.__name__ = name
    wrapper.__doc__ = getattr(fn, "__doc__", None)
    setattr(wrapper, "__wrapped__", fn)  # expose the original for introspection
    return wrapper


def require_package(import_name: str, pip_name: str):
    """Import a framework package or raise a helpful install hint."""
    try:
        return __import__(import_name)
    except ImportError as e:  # pragma: no cover - exercised only when missing
        raise ImportError(
            f"This adapter requires '{pip_name}'. Install it with: pip install {pip_name}"
        ) from e
