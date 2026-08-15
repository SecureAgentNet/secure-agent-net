# Type-checking policy

SecureAgentNet adopts static typing via a **ratchet**: the whole tree is checked
for signal, but an **enforced core** of security-critical modules is kept
mypy-clean and **gates CI**. The enforced set grows over time; it never shrinks.

## Two mypy passes in CI

The `typecheck` job (`.github/workflows/ci.yml`) runs two steps:

1. **Enforced core — gating.** `make typecheck-strict` runs
   `mypy --follow-imports=silent` over the enforced modules and **must pass** (no
   `continue-on-error`). `--follow-imports=silent` type-checks the enforced files
   fully while suppressing errors from imported-but-not-yet-enforced modules, so
   the gate reflects exactly the enforced set.
2. **Full package — advisory.** `mypy secureagentnet/ --ignore-missing-imports`
   runs for signal on everything else and does **not** gate (`continue-on-error:
   true`) while the remaining backlog is paid down.

## The enforced core (must stay clean)

Defined as `MYPY_ENFORCED` in the `Makefile`:

- `secureagentnet/decide/` — the DECIDE tiers (rule filter, AST verifier, PII
  gate, semantic evaluator, **pluggable model providers**, HITL, kill-switch,
  mandate registry, gateway).
- `secureagentnet/integrations/` — the framework adapters and executors
  (`secure_tool`/`secure_callable`, Local/Remote executors, wrappers).
- `secureagentnet/monitoring/` — host metrics + telemetry.
- `secureagentnet/cloud/` — the multi-tenant console API (RBAC, API keys,
  metering, migrations plumbing).

This is the code that makes and enforces the security decision, plus the agent
integration surface — the highest-value place to guarantee type safety.

## Exempted (advisory only, not gated)

Listed under `[[tool.mypy.overrides]]` in `pyproject.toml` with
`ignore_errors = true`. These are high-noise / low-value to annotate because
their errors come from conforming to third-party or dynamic surfaces:

- `secureagentnet.decide.pii_redactor` — matches Presidio `NlpEngine` override
  signatures (a `NoOp` engine); the stubs fight back.
- `secureagentnet.cloud.models`, `secureagentnet.database.models` — SQLAlchemy
  declarative `Column` typing.
- `secureagentnet.desktop.*` — PySide/Qt dynamic attributes.

## Growing the ratchet

1. Pick a module currently outside the enforced core (e.g. `identify/`,
   `track/`, `contain/`, `core/`), fix its mypy errors to zero.
2. Add it to `MYPY_ENFORCED` in the `Makefile`.
3. Run `make typecheck-strict` — it must be clean.
4. If a module is genuinely third-party-shaped noise, exempt it in
   `pyproject.toml` instead (and say why), rather than leaving the gate red.
5. Never let an already-enforced module regress: if you touch it, leave it clean.

## Running locally

```bash
pip install -e ".[dev]"
make typecheck-strict                              # the gating enforced-core pass
mypy secureagentnet/ --ignore-missing-imports      # full advisory report
```

## Why a ratchet instead of all-or-nothing

Blocking a large existing codebase on a full-strict pass would force one
enormous unreviewable PR or freeze other work. Enforcing a clean, security-
critical core and expanding outward keeps the guarantee real *today* on the code
that matters most, without holding delivery hostage — the same incremental
approach used by Django, pandas, and other mature Python projects.
