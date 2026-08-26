"""Small local payroll ledger used by the finance-agent demonstration.

This is intentionally a simulator: it writes payment records locally and never
contacts a bank, payment processor, or real account.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path


REGISTERED_EMPLOYEES = {
    "alice.smith": {"name": "Alice Smith", "account": "EMP-ALICE-001", "salary": 4200},
    "bob.jones": {"name": "Bob Jones", "account": "EMP-BOB-002", "salary": 3900},
}


@dataclass(frozen=True)
class Payment:
    employee: str
    amount: int
    recipient_account: str
    reference: str


class PayrollLedger:
    """A local, inspectable record of payments released by the demo."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.path = self.root / "payments.json"

    def seed(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.path.write_text("[]\n", encoding="utf-8")

    def employees(self) -> dict:
        return REGISTERED_EMPLOYEES.copy()

    def payments(self) -> list[dict]:
        if not self.path.exists():
            return []
        return json.loads(self.path.read_text(encoding="utf-8"))

    def transfer(self, employee: str, amount: int, recipient_account: str) -> str:
        """Record an approved transfer.

        The security decision belongs to SecureAgentNet, which wraps this
        function. The ledger has no network capability and is solely a visible
        side-effect for the demo.
        """
        payment = Payment(
            employee=employee,
            amount=int(amount),
            recipient_account=recipient_account,
            reference=f"PAY-{len(self.payments()) + 1:04d}",
        )
        records = self.payments()
        records.append(asdict(payment))
        self.path.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
        return f"Recorded {payment.reference}: {employee} → {recipient_account} ({amount})"
