"""A payment agent governed by SecureAgentNet before every simulated release."""
from __future__ import annotations

from secureagentnet.integrations.base import SecureExecutor
from secureagentnet.integrations.contract import AgentContract, bind_executor

from .contract import FINANCE_OPS_CONTRACT
from .models import PaymentState
from .payment_engine import FinanceOpsStore


class FinancePaymentAgent:
    """Processes one request at a time; never performs a payment without SAN."""

    def __init__(
        self, store: FinanceOpsStore, executor: SecureExecutor, agent_id: str,
        contract: AgentContract = FINANCE_OPS_CONTRACT,
    ):
        self.store = store
        self.executor = bind_executor(executor, contract)
        self.agent_id = agent_id
        self.contract = contract

    def process(self, request_id: str) -> dict:
        request = self.store.requests[request_id]
        existing = self.store.state(request_id)
        if existing["state"] in {PaymentState.REJECTED.value, PaymentState.RELEASED.value}:
            return existing

        # The untrusted source document and beneficiary are always sent to SAN
        # before a local business-rule decision or simulated transfer is made.
        decision = self.executor.adjudicate(
            action_name="transfer_funds",
            target_resource=request.account_reference,
            intent_summary=(
                "Release a payment only to a registered employee or approved vendor "
                "account under the commissioned FinanceOps payment mandate."
            ),
            payload=request.payload(),
        )
        if decision.get("status") != "allowed":
            state = PaymentState.AWAITING_APPROVAL if decision.get("status") == "escalated" else PaymentState.REJECTED
            return self.store.set_state(
                request_id, state, decision.get("reason", "SecureAgentNet denied the payment"),
                evaluated_by=decision.get("evaluated_by", "SecureAgentNet"),
            )

        valid, requires_human, reason = self.store.validate_business_rules(request)
        if not valid:
            return self.store.set_state(request_id, PaymentState.REJECTED, reason, evaluated_by="FinanceOpsRules")
        if requires_human:
            return self.store.set_state(request_id, PaymentState.AWAITING_APPROVAL, reason, evaluated_by="FinanceOpsRules")

        released = self.store.release(request, self.agent_id)
        return self.store.set_state(request_id, PaymentState.RELEASED, "Released to simulated payment rail", **released)

    def approve(self, request_id: str, approver_id: str) -> dict:
        """Second-person release for a SAN-approved request awaiting review."""
        current = self.store.state(request_id)
        if current["state"] != PaymentState.AWAITING_APPROVAL.value:
            return current
        if approver_id == self.agent_id:
            return self.store.set_state(request_id, PaymentState.REJECTED, "Dual approval requires a different operator")
        request = self.store.requests[request_id]
        valid, _, reason = self.store.validate_business_rules(request)
        if not valid:
            return self.store.set_state(request_id, PaymentState.REJECTED, reason, evaluated_by="FinanceOpsRules")
        released = self.store.release(request, approver_id)
        return self.store.set_state(
            request_id, PaymentState.RELEASED, "Released after two-person approval", approver_id=approver_id, **released
        )
