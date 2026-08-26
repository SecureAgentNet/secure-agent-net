# FinanceOps seed workbook

`finance_ops_seed.xlsx` is a one-sheet, fictional dataset for the SecureAgentNet
FinanceOps case study. It contains approved employees/vendors, normal payment
requests, approval rules, and adversarial payment scenarios.

All names, account references, invoices, and amounts are invented. Account
references are opaque test tokens, not bank-account numbers. Do not replace them
with real payroll, vendor, or banking data.

The CSV is the editable source; the accompanying workbook is generated from it so
it is easy to inspect in Excel or LibreOffice.

## Run the payment-agent simulation

```bash
python -m examples.finance_ops --provider classifier
```

To watch the agent from the Desktop application, share the Desktop daemon's
local SAN storage:

```bash
python -m examples.finance_ops --provider classifier --san-data-dir ~/.secureagentnet
```

The agent authenticates to the SecureAgentNet MCP gateway before every payment
request. The local FinanceOps rules then validate the approved beneficiary,
idempotency key, and approval threshold. Released records are written only to
`/tmp/san-finance-ops/released_payments.json`; no bank or payment-provider API is
called.

## Run with a LangChain coordinator

With Ollama and `llama3.2` available, let a real LangChain agent choose its
inspection and processing tools. The coordinator cannot bypass the payment state
machine or SAN gateway:

```bash
pip install -e ".[agents]"
python -m examples.finance_ops --langchain --provider classifier
```

The model receives only three tools: list requests, inspect a request, and submit
an existing request to the governed workflow. The transfer-specific tool sends the
full source document, amount, and beneficiary through SecureAgentNet before the
simulated rail can change.

Every run is labelled with a framework-neutral agent contract. The contract records
the project, coordinator framework, role, mandate, capabilities, and finance
simulation metadata. This is the boundary future AutoGen, CrewAI, and custom-agent
adapters must implement; the Desktop and `san` CLI can then inspect all of them
through the same SecureAgentNet event model.

## Interactive prompt mode

Start a terminal conversation with the coordinator:

```bash
python -m examples.finance_ops --langchain --interactive --provider classifier
```

Useful prompts include:

```text
List the pending payment requests.
Inspect PAY-003 and explain whether it needs approval.
Process PAY-001.
Process ATT-001.
```

Type `quit` to exit. The coordinator receives only the three constrained tools;
it cannot invent a beneficiary, modify an account or amount, self-approve a
high-value payment, or bypass SecureAgentNet.
