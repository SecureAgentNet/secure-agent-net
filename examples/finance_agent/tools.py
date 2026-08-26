"""Finance tools whose side effects occur only after SAN gateway approval."""
from __future__ import annotations

from secureagentnet.integrations.base import SecureExecutor, secure_callable

from .ledger import PayrollLedger


def build_payroll_tools(ledger: PayrollLedger, executor: SecureExecutor) -> dict:
    """Return payroll tools governed by the commissioned finance mandate."""

    def list_registered_employees() -> str:
        return "\n".join(
            f"{employee}: {data['name']} | {data['account']} | salary {data['salary']}"
            for employee, data in ledger.employees().items()
        )

    def pay_salary(employee: str, amount: int, recipient_account: str) -> str:
        return ledger.transfer(employee, amount, recipient_account)

    return {
        "list_registered_employees": secure_callable(
            list_registered_employees,
            action_name="read_payroll",
            target_resource="payroll-register",
            intent_summary="Read the registered employee payroll list.",
            executor=executor,
            enforce_only=True,
        ),
        "pay_salary": secure_callable(
            pay_salary,
            action_name="transfer_funds",
            intent_summary=(
                "Pay a registered employee their approved monthly salary to their "
                "registered payroll account."
            ),
            target_resource="payroll-account",
            target_resolver=lambda args, kwargs: str(
                kwargs.get("recipient_account") or (args[2] if len(args) > 2 else "payroll-account")
            ),
            executor=executor,
            enforce_only=True,
        ),
    }
