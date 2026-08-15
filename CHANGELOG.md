# Changelog

## [Unreleased] — Industry-hardening & detection moat

### Added
- **Deterministic security verdicts**: the DECIDE LLM tier now decodes greedily with a fixed seed instead of sampling. The Ollama provider previously sent no `options`, so it ran at Ollama's default `temperature 0.8` — the same action could get different verdicts run-to-run, which is unacceptable for an enforcement decision. It now sends `options: {temperature: 0, seed, top_p: 1}` (configurable via `DECIDE_TEMPERATURE` / `DECIDE_SEED`), and the hosted-API provider sends a matching `seed`. Verified: the same request yields an identical verdict across repeated live runs.
- **Enforced typing ratchet**: mypy now **gates CI** on an enforced security-critical core (`decide/`, `integrations/`, `monitoring/`, `cloud/` — 44 files, 0 errors) via `make typecheck-strict` (`mypy --follow-imports=silent`), while the full-package pass stays advisory. Fixed ~18 real type errors in that core (including a latent `RemoteExecutor` bug that would pass `None` where a `str` client URL/agent-id/key is required). High-noise modules (Presidio `NoOp` engine, SQLAlchemy declarative models, Qt desktop) are explicitly exempted in `pyproject.toml`. Policy + how to grow the ratchet in `docs/engineering/TYPING.md`.
- **Real LangChain email agent (guarded test harness)** (`examples/langchain_email_agent/`): a genuine LangChain tool-calling agent (Ollama `llama3.2` brain via `create_agent`) that reads a support inbox and replies to customers, with **every tool call routed through the ITCD pipeline**. Its inbox carries an indirect prompt-injection email (OWASP LLM01) that tries to make the assistant exfiltrate a host secret to an attacker address — proving SAN governs a real agent, not just a synthetic corpus. Deterministic enforcement test (`tests/integration/test_langchain_email_agent.py`, offline `classifier` provider) asserts the benign reply is sent while the exfiltration reply and hijacked shell command are blocked.
- **Adjudicate-only tool enforcement** for framework adapters (`secure_tool(..., enforce_only=True)` / `secure_callable`): SAN *decides* (mandate + DECIDE) and, on approval, the tool's **real body runs in-process** — the right model for tools with genuine side effects (send an email, write a record, call an API), where sandboxing a synthetic shell command is wrong. A `target_resolver(args, kwargs)` derives the DECIDE target from the call's arguments (e.g. an email's recipient), so redirecting a reply to an external address is judged against the mandate on that very call. `LocalExecutor.adjudicate` provides the decision-only path (fail-closed on a missing/expired mandate or an action outside it).
- **Pluggable DECIDE model provider** (`DECIDE_MODEL_PROVIDER`): the Tier-3 semantic evaluator's model is now a swappable backend — `ollama` (local LLM, default), `hosted_api` (OpenAI-compatible chat API for the cloud tier), or `classifier` (small local model: HuggingFace text-classification if `transformers`+`CLASSIFIER_MODEL` are present, else a **fitted logistic-regression** over interpretable features — fast/offline, works in CI). Shared prompt + verdict→score mapping in `secureagentnet/decide/model_providers.py`; fail-closed deny on any provider outage, never cached.
- **Fitted classifier weights**: `scripts/fit_classifier.py` fits the `classifier` provider's logistic weights on the labelled corpus (pure-Python gradient descent, 5-fold cross-validated: ~100% detection / ~12.5% FP held-out) and ships them as `secureagentnet/decide/classifier_weights.json`, auto-loaded by the provider. Same feature extractor used at train and inference by construction.
- **Host-anomaly UI**: the desktop Host Monitor shows a live red banner + alarms the network gauge on an outbound-network spike — the same condition that makes DECIDE escalate exfiltration-shaped actions — so operators *see* the signal that drives escalation.
- **Live host telemetry** (`secureagentnet/monitoring/host_metrics.py`): psutil-backed CPU/memory/disk/network-throughput/top-processes for the host the endpoint protects; surfaced in the desktop **Host Monitor** page (animated gauges + streaming sparklines) and the `san host` CLI (`--watch`, `--json`).
- **Host telemetry → DECIDE** (`DECIDE_HOST_TELEMETRY`, off by default): a live host outbound-network spike during an exfiltration-shaped action raises the decision risk into the HITL escalation band (`HostTelemetryMonitor`, rolling baseline + spike detection). Additive only — never lowers a score or auto-denies. Ties "read the host" to catching data exfiltration (OWASP LLM06 / MITRE AML.T0025).
- **Per-agent resource attribution → rogue detection**: a sandbox's container counters (`network_tx_bytes`, `cpu_usage_percent`, OOM) are attributed to its agent; an anomalous egress/CPU/OOM event raises that agent's `RogueDetector` anomaly score and docks trust, naming *which* agent went rogue (connects CONTAIN telemetry to IDENTIFY rogue detection).
- **Security whitepaper** (`docs/SecureAgentNet_Whitepaper.md`): threat model, ITCD architecture, mandate-anchoring thesis with ablation evidence, standards alignment (OWASP LLM Top 10 / MITRE ATLAS / NIST AI RMF), pluggable providers, runtime behavioral defense, honest threats-to-validity, and the hybrid open-core deployment model.
- **Detection regression gate**: `scripts/run_evaluation.py --check` runs the deterministic Tier-1 (rule-only) baseline — no LLM/Ollama required — and fails CI if committed detection floors regress (`docs/evaluation/detection_thresholds.json`). Wired as the `detection-eval` CI job. Proven to fail on an impossible floor.
- **MITRE ATLAS coverage**: `tests/red_team/adversarial_dataset/standards_map.json` cross-walks the OWASP LLM Top 10 to MITRE ATLAS techniques/tactics and the ITCD defense tier. Harness emits `docs/evaluation/Standards_Coverage.md` (two-framework matrix + per-ATLAS-technique detection table).
- **Threshold analysis**: `docs/evaluation/Threshold_Analysis.md` — pure-Python ROC sweep of the block threshold from recorded risk scores, with ROC-AUC and F1/Youden-optimal operating points (no numpy/sklearn dependency).
- **Corpus expansion**: adversarial corpus 55 → 73 scenarios (indirect/tool-result injection, homoglyph obfuscation, markdown-image exfil, SSRF-to-metadata, DNS exfil, MCP tool-poisoning, rug-pull, privilege escalation, model distillation) with per-scenario ATLAS tags; benign corpus 25 → 40 false-positive near-misses (each constructed to pass the deterministic RuleFilter).
- **Observability/SRE**: structured JSON logging (`LOG_FORMAT=json`), a `/readyz` readiness probe (DB-backed, returns 503 when not ready) distinct from the `/health` liveness probe.
- **CI/quality gates**: Python 3.10–3.13 test matrix, coverage gate (`--cov-fail-under`), `.pre-commit-config.yaml`, gradual-typing policy (`docs/engineering/TYPING.md`).

- **Cloud console multi-tenancy (Pillar D)**: RBAC with an owner/admin/operator/viewer role hierarchy (`require_role` dependency; roles enforced on kill-switch, enrollment, user & API-key management); tenant-scoped programmatic **API keys** for a read-only **public API/SDK** (`/api/v1/public/events`, `/agents`); per-tenant **usage metering** (`UsageCounter`: events ingested + API calls) as the billing foundation, with an admin `/usage` endpoint.

- **Console dashboard UI for Pillar D**: the Astro console gained tabbed **Team** (RBAC — list/invite users, change roles), **API Keys** (create with one-time reveal, revoke), and **Usage** (per-period metering table) views; role decoded from the JWT gates owner/admin-only controls client-side (backend still enforces). The Team/API Keys/Usage **tabs are hidden below the admin role** (matching the read guards), and endpoint hostnames are no longer interpolated into inline event handlers (looked up via an id→name map) so a hostname can't break out of the JS string context.

- **Real LangChain email agent, governed by the MCP gateway** (`examples/langchain_email_agent/`): a genuine `llama3.2` tool-calling agent that reads a support inbox and replies to customers, where **every tool call is an authenticated `POST /api/v1/mcp/execute`** to a booted SecureAgentNet gateway (RSA keypair → challenge/sign/JWT → verdict). Ships a poisoned email (indirect prompt-injection, OWASP LLM01) and an adversarial probe that shows the gateway denying a hijacked exfiltration (`restricted path: /root`) even when the model itself resists. Proves SAN governs a real agent through its actual enforcement surface, not a synthetic corpus.
- **Adjudicate-only tool enforcement** (`secure_tool(..., enforce_only=True, target_resolver=...)`): a new mode for framework tools that have a **real local side effect** (send an email, write a record, call an API) where sandbox-executing a synthetic command is nonsensical. SAN *decides* (mandate + DECIDE, via `LocalExecutor.adjudicate` in-process or `RemoteExecutor.adjudicate` over the MCP gateway) and the tool's real body runs only on approval; `target_resolver` derives the DECIDE target from the call's arguments (e.g. an email's recipient) so a reply redirected to an external address is judged on that call. Fail-closed on any gateway/transport error. Default sandbox mode is unchanged and backward-compatible.
- **MCP execute can carry input files**: `ExecuteRequest.files` (and the pipeline) now inject `{path, content_base64}` files into the sandbox workspace before a tool command runs, so a tool call can bring its own input (e.g. an email to parse) into containment.
- **Cloud console DB migrations (Alembic)**: the console now owns its schema through a dedicated Alembic environment (`secureagentnet/cloud/migrations`) instead of `create_all` alone — `create_all` adds *missing tables* but never ALTERs an existing one, so an in-place upgrade of a pre-Pillar-D console DB would have been left without the `admin_users.role` column. Two idempotent revisions (baseline + Pillar-D) run automatically on startup (and via `secureagentnet-cloud --migrate` as a discrete deploy step); they adopt a DB previously created by `create_all` without a stamp, back-fill existing admins to `owner`, and are safe to re-run. The cloud Docker image now bundles `alembic`; `create_all` remains only as a last-resort fallback.

### Changed
- **Benchmark refreshed** over the expanded 73-attack / 40-benign corpus (3 runs, `llama3.2`): full pipeline detection **97.7%** (95.9–98.6%), hard-FP **0.8%**, specificity 92.5%, F1 0.964, ROC-AUC 0.976. **Mandate-ablation refreshed** too: detection stays ~100% but specificity collapses to **37.5%** and goal-hijacking drops 6/6 → 3/6 — the thesis, re-confirmed on the harder corpus (`Ablation_and_Baselines.md`).
- **Made the LangChain email-agent example re-runnable**: the gateway persists denial/kill-switch/circuit-breaker/rogue state across processes (correct in production), but the example re-uses one agent against a shared local DB, so each run's adversarial probe added a denial and — at the default kill-switch threshold of 3 — the third run tripped the switch and halted all operations. `runtime.reset_enforcement_state()` now re-baselines that state at startup (before the gateway boots), and the agent's `recursion_limit` was raised so a small model can recover from a wrong-argument tool call. Verified live end-to-end across the classifier and Ollama DECIDE brains (benign + poisoned inboxes); back-to-back runs stay clean.
- **Fixed cross-test state leakage from the RogueDetector singleton**: `get_rogue_detector()` returns a process-wide instance shared by every pipeline, so a test that tuned its thresholds (e.g. `_rate_limit=1`) leaked into later tests and spuriously flagged fresh agents as rogue ("rate limit exceeded"), failing five unrelated integration tests only when the full suite ran together. Added `RogueDetector.reset()` (re-arm: drop learned profiles, restore default thresholds) and call it in the test reset fixture. Full suite now green together (759 passed).
- **Fixed a classifier false-positive**: the `classifier` DECIDE provider tokenized the commissioned goal with a bare `split()`, so punctuation-glued tokens (`"send_email)."`, `"secrets,"`) could never match the request text and `goal_mismatch` fired on legitimate actions. Now tokenized on word characters (keeping snake_case action names whole); weights refit (unchanged 100% / 12.5% held-out). Only affects the offline `classifier` provider — the LLM benchmark and the rule-only CI gate are unaffected.
- **Fixed broken CI**: all workflows and the `Makefile` referenced the old `src/` path (package was renamed to `secureagentnet/`), so `flake8`/`mypy`/`bandit` silently checked a non-existent directory. Now corrected — CI actually enforces again.
- **Dockerfile hardened**: runs as a non-root `app` user.
- Migrated all Pydantic models from deprecated class-based `Config` to `ConfigDict` (Pydantic v3-ready); cleaned test `return`→helper and invalid-escape warnings.

## [2.0.0] — 2026-05-24

### Added
- **Phase A — Database Migration**: 12 SQLAlchemy ORM models, 5 repository classes with transparent JSON fallback, SQLite default for dev, PostgreSQL for production, Alembic with initial migration.
- **Phase B — Pipeline Reordering**: ITCD pipeline now flows IDENTIFY → TRACK → CONTAIN → DECIDE. `ReasoningCaptureMiddleware` wired into main flow with pre-execution Vault logging and `PipelineBlockedError` handling.
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
- Initial release: ITCD Pipeline (Identify → Track → Contain → Decide).
- CLI with 14 subcommands (`secureagentnet`/`san`).
- Flask web dashboard with login, agent management, forensics, security panels.
- FastAPI gateway with challenge-response authentication.
- Docker sandbox with seccomp profile.
- Regex-based PII redaction (email, phone, SSN, credit card).
- Ollama LLM semantic evaluation with retry/backoff.
- HashiCorp Vault KV v2 for audit log storage.
- Redis rate limiting with in-memory fallback.
- Circuit breaker and kill-switch for agent isolation.
