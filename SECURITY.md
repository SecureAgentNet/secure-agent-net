# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 2.0.x   | :white_check_mark: |
| < 2.0   | :x:                |

## Architecture

SecureAgentNet implements a **zero-trust security model** through a 4-phase pipeline:

```
IDENTIFY → TRACK → CONTAIN → DECIDE
```

Every agent action passes through all four phases before execution. No phase trusts the output of any other phase — each independently validates and re-checks.

| Phase    | Checks |
|----------|--------|
| IDENTIFY | Identity registration, capability authorization, rogue detection, circuit breaker, kill-switch |
| TRACK    | Intent capture to Vault (Transit HMAC-signed) before execution |
| CONTAIN  | Docker sandbox with seccomp, AppArmor, read-only rootfs, dropped capabilities, network isolation |
| DECIDE   | 3-tier evaluation: RuleFilter → PiiRedactor (Presidio) → SemanticEvaluator (LLM) |

## Security Features

### Fail-Closed Default
- Unavailable services (LLM, Vault, Redis) result in **denial (score 1.0)**, not allowance.
- `PiiRedactor` failure triggers `PIIRedactionError` → deny in `DecisionGateway`.
- Ollama retries with exponential backoff; final failure → deny.

### Container Sandbox
- **seccomp**: Whitelist of 76 syscalls only; all others `SCMP_ACT_ERRNO`.
- **AppArmor**: Denies `proc/sys`, `/sys/`, `/boot/`, `/root/`, `/etc/shadow`, raw/packet sockets, all capabilities.
- **Capabilities**: All dropped (`cap_drop: ["ALL"]`).
- **Read-only rootfs** with `tmpfs` for scratch space (`noexec,nosuid,nodev`).
- **Network isolation**: Default `none`; configurable strict/moderate/permissive.
- **Container limits**: Per-agent maximum (3) + global maximum (10).
- **OOM detection**: Reads `State.OOMKilled` from Docker inspect.
- **Timeouts**: Configurable per SandboxConfig (`container_timeout_seconds`).

### Audit Logging
- All agent actions logged to Vault's **Transit engine** (HMAC-SHA256 signed).
- `forensics verify <receipt>` command for log integrity verification.
- `DecisionLog` persisted to database with per-tier scores and timing.

### Authentication & Authorization
- **Challenge-response**: Agent signs a nonce with its Ed25519/RSA private key.
- **JWT**: Short-lived access tokens (HS256, configurable expiry).
- **IntentCapsule**: Session-scoped goal validation; goal-hijack detection.
- **CapabilityProfiler**: Per-agent allowed action whitelist.

### PII Protection
- **Microsoft Presidio** with 6 built-in recognizers (email, phone, SSN, credit card, IP, passport).
- All payloads redacted before reaching the LLM. Score threshold configurable.

### Rate Limiting & Circuit Breaking
- **Redis-backed** rate limiting with in-memory fallback.
- **CircuitBreaker**: Per-agent failure tracking; auto-opens after threshold, auto-resets after timeout.
- **KillSwitch**: System-wide emergency halt; denial counts persisted to database.

### Cryptographic Verification
- `verify_signature()` supports RSA (PSS/SHA-256) and EC (ECDSA/SHA-256).
- `generate_nonce()` uses `secrets.token_hex(32)`.
- `create_access_token()` / `decode_access_token()` with expiry validation.

## Reporting a Vulnerability

**Do not open a public issue.** Email:

```
secureagentnet@example.com
```

Include:
- Affected version
- Steps to reproduce
- Impact assessment
- Any proposed fix (optional)

Response within 48 hours. We follow a 90-day coordinated disclosure timeline.

## Deployment Modes

| Mode    | Docker | Redis | Ollama | Vault | Use Case |
|---------|--------|-------|--------|-------|----------|
| `docker` | ✓ | ✓ | ✓ | ✓ | Production (full security) |
| `local`  | ✗ | ✗ | ✗ | ✗ | Development (SQLite, no containers) |
| `minimal` | ✗ | ✗ | ✗ | ✗ | Quick evaluation (JSON files, no external services) |

Set via `DEPLOY_MODE` env var or `secureagentnet init --mode <mode>`.

## Platform Support

| OS       | Docker | AppArmor | seccomp | Notes |
|----------|--------|----------|---------|-------|
| Linux    | ✓ native | ✓ | ✓ | Full security features |
| macOS    | Docker Desktop | ✗ | ✗ | Container sandboxing works; AppArmor/seccomp skipped |
| Windows  | Docker Desktop | ✗ | ✗ | Container sandboxing works; AppArmor/seccomp skipped |
