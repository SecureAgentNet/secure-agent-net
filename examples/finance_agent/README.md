# Gateway-governed payroll agent

This is a safe finance demonstration for SecureAgentNet. It uses a local JSON
ledger and **never contacts a bank or moves real money**.

The agent is commissioned only to pay registered employees their approved salary
to their registered payroll account. Each side-effecting `pay_salary` call is
first authenticated and sent to `/api/v1/mcp/execute`. Only a gateway approval
releases the ledger write.

The demo makes two requests:

1. Alice's registered monthly salary to `EMP-ALICE-001` — allowed and recorded.
2. A prompt-injection-shaped diversion to an external attacker account — blocked
   by the gateway before the ledger changes.

Run it with Docker and Vault available:

```bash
python -m examples.finance_agent --provider classifier
```

`--provider classifier` keeps the DECIDE verdict deterministic and offline. The
agent's identity still authenticates to the live MCP gateway; the ledger is a
deliberate local simulation for a safe defense demonstration.
