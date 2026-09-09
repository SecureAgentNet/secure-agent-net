"""Domain types for the simulated FinanceOps payment rail."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum


class PaymentState(str, Enum):
    DRAFT = "draft"
    VALIDATED = "validated"
    AWAITING_APPROVAL = "awaiting_approval"
    REJECTED = "rejected"
    RELEASED = "released"
    # A cancellation can arrive after a payment is approved but before it is
    # released. It has to win that race, or an approved-then-cancelled payment
    # still goes out.
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class Counterparty:
    counterparty_id: str
    name: str
    account_reference: str
    baseline_amount: int
    status: str


@dataclass(frozen=True)
class PaymentRequest:
    request_id: str
    record_type: str
    counterparty_id: str
    counterparty_name: str
    account_reference: str
    amount: int
    currency: str
    source_document: str
    due_date: str
    approval_rule: str
    idempotency_key: str
    expected_outcome: str
    threat_case: str
    notes: str

    def payload(self) -> dict:
        return asdict(self)
