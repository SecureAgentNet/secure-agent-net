# Phase 2 — TRACK: Architecture & Design

## Overview

TRACK is the second phase of the ITCD pipeline. Its purpose is to **capture agent intent and reasoning before execution**, ensuring a tamper-proof audit trail even for actions that are later blocked.

```
IDENTIFY → TRACK → CONTAIN → DECIDE
              ↑
     Intent captured here,
     before any decision is made
```

## Design Rationale

In the original pipeline (v1.0.0), TRACK ran AFTER the DECIDE + CONTAIN phases:

```
v1.0:  IDENTIFY → DECIDE → CONTAIN → TRACK
v2.0:  IDENTIFY → TRACK → CONTAIN → DECIDE
```

**Problem with v1.0**: Blocked actions were never logged. If the pipeline denied a request at the IDENTIFY or DECIDE phase, the agent's intent was never captured. This made forensic investigation impossible — there was no record of what the agent was *trying* to do.

**Solution in v2.0**: `ReasoningCaptureMiddleware` wraps the DECIDE+CONTAIN phases, capturing intent to Vault before any decision is made. Even if the action is blocked, the Vault receipt exists.

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        TRACK PHASE                               │
│                                                                  │
│  ┌──────────────────────┐    ┌─────────────────────────────┐    │
│  │ ReasoningCapture     │    │ VaultAuditClient             │    │
│  │ Middleware            │───▶│                              │    │
│  │                      │    │  sign_log()  → Transit HMAC  │    │
│  │ capture_and_evaluate │    │  secure_log() → KV v2 store  │    │
│  │   ├─ Pre: log intent │    │  verify_log() → HMAC check   │    │
│  │   ├─ Exec: callback  │    │  verify_receipt() → tamper?  │    │
│  │   └─ Post: update    │    └─────────────────────────────┘    │
│  └──────────────────────┘                                       │
│           │                                                      │
│           ▼                                                      │
│  ┌──────────────────────┐    ┌─────────────────────────────┐    │
│  │ AgentAuditor          │    │ LogIndexer                   │    │
│  │                      │    │                              │    │
│  │  capture()           │    │  index_event()  → in-memory │    │
│  │  → CapturedLog       │    │  query_by_agent()            │    │
│  │  → vault_receipt_id  │    │  query_by_phase()            │    │
│  └──────────────────────┘    │  search()                     │    │
│                               └─────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────┘
```

## Components

### 1. `ReasoningCaptureMiddleware` (`src/track/reasoning_capture.py`)

The middleware pattern that wraps execution with pre/post logging.

```python
async def capture_and_evaluate(agent_id, request, execute_callback):
    # Pre-execution: capture intent to Vault
    log_event = CapturedLog(agent_id=agent_id, action_request=request, decision="pending")
    log_event = auditor.capture(log_event)

    try:
        # Execute the DECIDE → CONTAIN callback
        result = await execute_callback()
        log_event.decision = "allowed"
        return {"status": "success", "vault_receipt": log_event.vault_receipt_id, "data": result}
    except PipelineBlockedError as blocked:
        log_event.decision = "blocked"
        return {"status": "blocked", ...}
    except Exception as e:
        log_event.decision = "failed"
        return {"status": "error", ...}
```

**Key property**: The `PipelineBlockedError` is handled specially. When the DECIDE phase blocks an action, the middleware catches the exception and returns `{"status": "blocked"}` with the Vault receipt — ensuring the blocked intent is logged.

### 2. `VaultAuditClient` (`src/track/vault_client.py`)

Two storage backends:

| Method | Engine | Purpose |
|--------|--------|---------|
| `sign_log(data)` | Transit | HMAC-SHA256 of canonical JSON |
| `verify_log(data, hmac)` | Transit | Verify HMAC matches |
| `secure_log(data)` | KV v2 | Store log + HMAC in Vault |
| `retrieve_log(receipt)` | KV v2 | Fetch by receipt |
| `verify_receipt(receipt)` | Both | Full integrity check |

**Canonical JSON**: `json.dumps(data, sort_keys=True, separators=(",", ":"))` ensures deterministic serialization. The HMAC is computed over this canonical form, so verification is reproducible.

**Transit Key**: Auto-created as `audit-log-key` (type: `hmac`, key_size: 0 for SHA-256). If Vault is unavailable, `sign_log()` returns `None` and `secure_log()` skips the HMAC field.

**Receipt Format**: `vault-audit/agents/{agent_id}/{log_id}-v{version}`. The version from KV v2 provides an additional integrity check — if someone overwrites the secret, the version changes.

### 3. `AgentAuditor` (`src/track/structured_logger.py`)

Bridge between the pipeline and Vault:

```python
class AgentAuditor:
    def capture(self, log_event: CapturedLog) -> CapturedLog:
        log_dict = json.loads(log_event.model_dump_json())
        vault_receipt = self.vault_client.secure_log(log_dict)
        if vault_receipt:
            log_event.vault_receipt_id = vault_receipt
        return log_event
```

On success, `CapturedLog.vault_receipt_id` is populated. This flows back through the middleware to the pipeline response as `"vault_receipt"`.

### 4. `LogIndexer` (`src/track/log_indexer.py`)

In-memory event index with database persistence. Provides:

- `index_event(event)` — append event with phase/severity/agent metadata
- `query_by_agent(agent_id)` — timeline for a specific agent
- `query_by_phase(phase)` — events filtered by ITCD phase
- `query_by_severity(severity)` — security-relevant events
- `search(query)` — full-text search across summaries
- `count_by_phase()` / `count_by_severity()` — aggregation

### 5. `ForensicQueryEngine` (`src/track/forensic_query.py`)

High-level query API used by CLI commands (`forensics query`, `forensics summary`, `forensics export`).

## Data Models

### `CapturedLog` (Pydantic)
```python
class CapturedLog(BaseModel):
    log_id: str           # UUID
    agent_id: str
    timestamp: datetime
    action_request: AgentActionRequest
    risk_score: Optional[float]
    decision: str         # "pending" → "allowed" | "blocked" | "failed"
    vault_receipt_id: Optional[str]
```

### `AgentActionRequest` (Pydantic)
```python
class AgentActionRequest(BaseModel):
    action_name: str      # e.g., "read_file", "execute_sql"
    target_resource: str  # e.g., "users_table", "/etc/config"
    intent_summary: str   # Agent's stated reason
    payload: Dict
```

## CLI Commands

```bash
# Query forensic events
secureagentnet forensics query --agent <id> --phase TRACK --limit 50

# Show agent timeline
secureagentnet forensics timeline <agent-id>

# Verify log integrity via Vault Transit
secureagentnet forensics verify vault-audit/agents/<id>/<log>-v3

# Export forensic data
secureagentnet forensics export --format json

# System summary
secureagentnet forensics summary
```

## Verification Flow

```
                   ┌──────────────────┐
                   │ forensics verify │
                   │   <receipt>      │
                   └────────┬─────────┘
                            │
                   ┌────────▼─────────┐
                   │ retrieve_log()   │
                   │ Parse vault-...-vN│
                   └────────┬─────────┘
                            │
                   ┌────────▼─────────┐
                   │ Extract _hmac    │
                   │ from stored data │
                   └────────┬─────────┘
                            │
                   ┌────────▼─────────┐
                   │ verify_log()     │
                   │ Canonical JSON   │
                   │ → verify_hmac()  │
                   └────────┬─────────┘
                            │
              ┌─────────────┴─────────────┐
              │                           │
     ┌────────▼────────┐        ┌────────▼────────┐
     │  ✓ HMAC matches │        │  ✗ Tampered     │
     │  Log is intact  │        │  Reason: H/M/S   │
     └─────────────────┘        └─────────────────┘
```

## Failure Modes

| Scenario | Behavior |
|----------|----------|
| Vault unreachable | `secure_log()` returns `None`; audit log entry created locally only |
| Transit key missing | Auto-created on first use; falls through if creation fails |
| HMAC mismatch on verify | Returns `{"valid": False, "error": "HMAC mismatch"}` |
| Receipt format invalid | `retrieve_log()` returns `None` |
| `PipelineBlockedError` in callback | Caught by middleware, log marked `"blocked"`, Vault receipt still issued |
| Generic exception in callback | Caught by middleware, log marked `"failed"` |

## Design Decisions

1. **HMAC over hash**: `generate_hmac()` uses the Transit key as the HMAC secret. This prevents offline tampering — an attacker with Vault read access cannot forge a valid HMAC without access to the Transit key's HMAC secret.

2. **Canonical JSON for determinism**: Python dict ordering, whitespace, and key sorting can affect the serialized output. Canonical JSON ensures the same data always produces the same HMAC.

3. **Pre-execution capture**: Intent is logged to Vault before DECIDE runs. Even if the agent is blocked, the intent is auditable. This is critical for forensic investigation of attack attempts.

4. **Transit key per-instance**: The `audit-log-key` is created on first use. In production, this key should be created by an operator with appropriate Vault policy (`create`, `update` on `transit/keys/audit-log-key`).
