# Changelog

## [2.0.0] — 2026-05-24

### Added
- **Phase A — Database Migration**: 12 SQLAlchemy ORM models, 5 repository classes with transparent JSON fallback, SQLite default for dev, PostgreSQL for production, Alembic with initial migration.
- **Phase B — Pipeline Reordering**: ITCD pipeline now flows IDENTIFY → TRACK → DECIDE → CONTAIN. `ReasoningCaptureMiddleware` wired into main flow with pre-execution Vault logging and `PipelineBlockedError` handling.
- **Phase C — Vault Transit Engine**: HMAC-SHA256 signing of all audit logs via HashiCorp Vault Transit. `forensics verify` CLI command for log integrity verification. `verify_receipt()` method with tamper detection.
- **Phase D — Presidio PII Redaction**: Microsoft Presidio replaces regex-based PII detection. 6 built-in recognizers (EMAIL_ADDRESS, PHONE_NUMBER, US_SSN, CREDIT_CARD, IP_ADDRESS, US_PASSPORT). `NoOpNlpEngine` avoids 400MB spaCy model download. `PIIRedactionError` now fails-closed in DecisionGateway.
- **Phase E — MCP Gateway**: JWT validation middleware (`get_current_agent` FastAPI dependency). 7 protected MCP routes: `/tools`, `/execute`, `/agent`, `/heartbeat`, `/capabilities`, `/auth/challenge`, `/auth/login`, `/auth/refresh`. `decode_access_token()` with expiry validation.
- **Phase F — AppArmor & Cross-Platform**: AppArmor profile written to `~/.secureagentnet/profiles/` with manual load script. `DEPLOY_MODE` config (`docker`/`local`/`minimal`). Platform detection (Linux/macOS/Windows). Docker Desktop socket detection. `scripts/install.sh` one-liner installer. Homebrew formula (`packaging/homebrew/`). AUR PKGBUILD (`packaging/aur/`).
- **Phase G1 — Test Coverage**: 25 credential exfiltration red-team tests. 6 container provisioner tests (files, exec form, OOM, custom timeout). DecisionGateway tests (block threshold, PiiRedactor fail-closed).

### Changed
- `DecisionGateway` now reads `BLOCK_THRESHOLD` from config instead of hardcoded 0.7.
- `RuleFilter` loads policies from database with hardcoded fallback.
- `DecisionLog` now persisted to database on every decision.
- `KillSwitchController` denial counts persisted and restored across restarts.
- `IntentCapsule` wired into the IDENTIFY phase (expiry, goal-hijack, forbidden actions).
- `ContainerProvisioner` now integrated with `ContainerResourceManager` for lifecycle tracking.
- `SandboxConfig` gained `network_isolation_level`, `timeout_seconds`, container limits.
- `ExecutionRequest` gained `args` (exec form), `files` (base64-encoded script injection).
- `ExecutionResult` gained `oom_killed`, `resource_usage` (CPU/memory/network metrics).
- Seccomp profile reconciled: config file and inline default are now identical.
- `setup.py` simplified to delegate to `pyproject.toml`.
- `pytest.ini` updated with marker definitions.
- `.env` cleaned of hardcoded secrets and stale defaults.
- All service URLs default to `127.0.0.1` (IPv4) instead of `localhost`.

### Removed
- `sudo` calls from AppArmor profile loader (now manual, via `scripts/load_apparmor.sh`).
- Dead dependencies: `python-dotenv`, `psycopg2-binary`, `flask-jwt-extended`, `prometheus-client`, `structlog`, `psutil`.
- Duplicate `get_settings()` function in `src/core/config.py`.
- Hardcoded `VAULT_TOKEN=root` from `.env`.

### Fixed
- IPv4 resolution: Python resolves `localhost` to `::1` (IPv6) but services listen on `127.0.0.1`.
- Docker socket detection for Docker Desktop on macOS and Windows.
- In-memory SQLite per test via `mock_settings` autouse fixture (env var approach).
- Seccomp profile written to temp file (Docker SDK v7 doesn't support inline JSON).
- KillSwitch denial counts now persist across restarts.

## [1.0.0] — 2025-11-01

### Added
- Initial release: ITCD Pipeline (Identify → Decide → Contain → Track).
- CLI with 14 subcommands (`secureagentnet`/`san`).
- Flask web dashboard with login, agent management, forensics, security panels.
- FastAPI gateway with challenge-response authentication.
- Docker sandbox with seccomp profile.
- Regex-based PII redaction (email, phone, SSN, credit card).
- Ollama LLM semantic evaluation with retry/backoff.
- HashiCorp Vault KV v2 for audit log storage.
- Redis rate limiting with in-memory fallback.
- Circuit breaker and kill-switch for agent isolation.
