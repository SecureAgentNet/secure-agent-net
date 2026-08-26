"""Local, auditable payment engine for the FinanceOps security case study.

The engine is intentionally a payment *simulator*. It stores released payments in
JSON and has no code for bank connections, card data, or real funds.
"""
from __future__ import annotations

import csv
import json
from dataclasses import asdict
from pathlib import Path

from .models import Counterparty, PaymentRequest, PaymentState


class FinanceOpsStore:
    def __init__(self, source: Path, root: Path):
        self.source = Path(source)
        self.root = Path(root)
        self.state_path = self.root / "payment_states.json"
        self.rail_path = self.root / "released_payments.json"
        self.counterparties: dict[str, Counterparty] = {}
        self.requests: dict[str, PaymentRequest] = {}

    def load(self) -> None:
        with self.source.open(newline="", encoding="utf-8") as stream:
            for row in csv.DictReader(stream):
                if row["record_type"] in {"employee", "vendor"}:
                    self.counterparties[row["counterparty_id"]] = Counterparty(
                        counterparty_id=row["counterparty_id"],
                        name=row["counterparty_name"],
                        account_reference=row["account_reference"],
                        baseline_amount=int(row["amount"]),
                        status=row["status"],
                    )
                elif row["record_type"] in {"payment_request", "attack_case"}:
                    self.requests[row["record_id"]] = PaymentRequest(
                        request_id=row["record_id"], record_type=row["record_type"],
                        counterparty_id=row["counterparty_id"],
                        counterparty_name=row["counterparty_name"],
                        account_reference=row["account_reference"], amount=int(row["amount"]),
                        currency=row["currency"], source_document=row["source_document"],
                        due_date=row["due_date"], approval_rule=row["approval_rule"],
                        idempotency_key=row["idempotency_key"],
                        expected_outcome=row["expected_system_outcome"],
                        threat_case=row["threat_case"], notes=row["notes"],
                    )
        self.root.mkdir(parents=True, exist_ok=True)
        if not self.state_path.exists():
            self._write_json(self.state_path, {})
        if not self.rail_path.exists():
            self._write_json(self.rail_path, [])

    @staticmethod
    def _write_json(path: Path, value: object) -> None:
        path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

    def _states(self) -> dict:
        return json.loads(self.state_path.read_text(encoding="utf-8"))

    def state(self, request_id: str) -> dict:
        return self._states().get(request_id, {"state": PaymentState.DRAFT.value})

    def set_state(self, record_id: str, state: PaymentState, reason: str, **extra: object) -> dict:
        states = self._states()
        states[record_id] = {"state": state.value, "reason": reason, **extra}
        self._write_json(self.state_path, states)
        return states[record_id]

    def released_payments(self) -> list[dict]:
        return json.loads(self.rail_path.read_text(encoding="utf-8"))

    def is_duplicate(self, request: PaymentRequest) -> bool:
        if not request.idempotency_key:
            return False
        return any(p.get("idempotency_key") == request.idempotency_key for p in self.released_payments())

    def validate_business_rules(self, request: PaymentRequest) -> tuple[bool, bool, str]:
        """Return ``(valid, requires_human_approval, explanation)``."""
        if self.is_duplicate(request):
            return False, False, "Duplicate idempotency key: payment was already released"
        counterparty = self.counterparties.get(request.counterparty_id)
        if counterparty is None:
            return False, False, "Counterparty is absent from the approved register"
        if counterparty.status not in {"active", "approved"}:
            return False, False, "Counterparty is not active/approved"
        if request.account_reference != counterparty.account_reference:
            return False, False, "Beneficiary account does not match the approved register"
        changed_amount = request.amount != counterparty.baseline_amount
        requires_human = request.amount > 5000 or changed_amount
        if requires_human:
            return True, True, "High-value or changed-amount payment requires two-person approval"
        return True, False, "Approved counterparty and baseline amount"

    def release(self, request: PaymentRequest, released_by: str) -> dict:
        if self.is_duplicate(request):
            raise ValueError("Duplicate payment release attempted")
        payment = {
            **asdict(request), "released_by": released_by,
            "transaction_id": f"SIM-TXN-{len(self.released_payments()) + 1:04d}",
        }
        payments = self.released_payments()
        payments.append(payment)
        self._write_json(self.rail_path, payments)
        return payment
