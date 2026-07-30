# Type-checking policy

SecureAgentNet is adopting static typing **gradually**. `mypy` runs on every CI
build but is currently **non-blocking** (`continue-on-error: true` on the
`typecheck` job) while a backlog of pre-existing errors is paid down.

## Current state

As of the CI wiring fix (package rename `src/` → `secureagentnet/`), `mypy
secureagentnet/ --ignore-missing-imports` reports **~119 errors across 31
files**. Before the fix, mypy was pointed at a directory that no longer existed,
so it silently checked nothing — these errors were always present, just hidden.

## The ratchet

1. Pick a package (start with the smallest / most-core: `core/`, then `decide/`,
   `identify/`), fix its errors, and add it to a `strict`-checked allowlist.
2. When the global count reaches **0**, flip `continue-on-error` to `false` in
   `.github/workflows/ci.yml` so type regressions block the build.
3. Never let the count go *up*: if you touch a file, leave it no worse typed.

## Running locally

```bash
pip install -e ".[dev]"
mypy secureagentnet/ --ignore-missing-imports        # full report
mypy secureagentnet/core --ignore-missing-imports    # one package
```

## Why non-blocking first

Blocking a large legacy codebase on a full-strict pass would either force a
single enormous unreviewable PR or freeze all other work. Gradual typing keeps
the signal visible on every PR without holding delivery hostage — the same
approach used by Django, pandas, and other mature Python projects.