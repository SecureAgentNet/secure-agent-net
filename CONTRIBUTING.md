# Contributing to SecureAgentNet

## Setup

```bash
git clone https://github.com/secure-agent-net/secure-agent-net.git
cd secure-agent-net
python -m venv venv
source venv/bin/activate   # or venv\Scripts\activate on Windows
pip install -e ".[dev]"
```

## Verify

```bash
secureagentnet doctor
pytest tests/unit/ tests/red_team/ -v
```

## Project Structure

```
src/
├── core/           # Pipeline, config, constants, exceptions
├── identify/       # Agent registry, auth, rogue detection, capabilities
├── track/          # Vault client, log indexer, reasoning capture, forensics
├── decide/         # DecisionGateway (3-tier), RuleFilter, PiiRedactor, SemanticEvaluator
├── contain/        # ContainerProvisioner, network isolation, resource manager
├── database/       # ORM models, repositories, Alembic migrations
├── utils/          # Crypto, validators, helpers, redis client, platform detection
└── interfaces/     # CLI (click), web dashboard (Flask/FastAPI)
test/
├── unit/           # Per-component unit tests
├── red_team/       # Adversarial tests (prompt injection, goal hijacking, credential exfil)
└── integration/    # End-to-end pipeline and API tests
```

## Development Workflow

### Running Tests

```bash
# All unit + red team tests
pytest tests/unit/ tests/red_team/ -v

# Specific component
pytest tests/unit/test_decide/ -v

# Integration tests (requires httpx)
pytest tests/integration/ -v

# Red team only
pytest tests/red_team/ -m redteam -v
```

### Code Style

- Line length: 100 characters (Black + isort)
- Python 3.10+ syntax
- Type hints on public APIs

```bash
black src/ tests/
isort src/ tests/
mypy src/
```

### Database Migrations

```bash
# Create a new migration
alembic -c alembic.ini revision --autogenerate -m "description"

# Apply migrations
alembic -c alembic.ini upgrade head

# Test database path: ~/.secureagentnet/data/securenet.db
# Test database URL: sqlite:///:memory: (auto-wired by conftest.py)
```

### Testing Principles

- **Unit tests** must not require external services (Docker, Redis, Vault, Ollama).
- **Red team tests** simulate adversarial inputs against the pipeline.
- **Integration tests** may require `httpx` for API endpoint testing.
- `mock_settings` fixture (autouse) sets `sqlite:///:memory:` and test environment vars.
- All stateful repositories cleared between tests via `reset_*` fixtures.

## Security Considerations

- Never commit secrets, API keys, or credentials.
- `.env` should be in `.gitignore` (use `.env.example` for documentation).
- Use `secrets.token_hex()` for key generation, not `random`.
- All LLM inputs must be PII-redacted before sending to Ollama.
- Container sandbox runs with strict seccomp + AppArmor + read-only rootfs.

## Pull Requests

1. Fork and branch from `main`.
2. Add tests for new functionality.
3. Run `pytest` and ensure all existing tests pass.
4. Run `black src/ tests/` and `isort src/ tests/`.
5. Open PR with a clear description.

## Release Process

1. Update version in `pyproject.toml` and `src/core/config.py`.
2. Update `CHANGELOG.md`.
3. Build wheel: `python -m build --wheel`.
4. Tag release: `git tag vX.Y.Z && git push --tags`.
5. Publish to PyPI: `twine upload dist/*`.
6. Update Homebrew formula SHA256 and AUR PKGBUILD checksum.
