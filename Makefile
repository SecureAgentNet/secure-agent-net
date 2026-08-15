.PHONY: install install-dev test test-unit test-redteam lint format typecheck doctor clean build

install:
	pip install -e .

install-dev:
	pip install -e ".[dev]"

test:
	pytest tests/unit/ tests/red_team/ -v --timeout=30

test-unit:
	pytest tests/unit/ -v --timeout=30

test-redteam:
	pytest tests/red_team/ -v --timeout=30

test-coverage:
	pytest tests/unit/ tests/red_team/ -v --timeout=30 --cov=secureagentnet --cov-report=term-missing

lint:
	flake8 secureagentnet/ tests/
	pylint secureagentnet/ || true

format:
	black secureagentnet/ tests/
	isort secureagentnet/ tests/

# Enforced-core typing gate (ratchet — see docs/engineering/TYPING.md). These
# security-critical modules must stay mypy-clean; CI fails if they regress.
# --follow-imports=silent checks these files fully while suppressing noise from
# imported-but-not-yet-enforced modules. Grow this list as more modules are typed.
MYPY_ENFORCED = secureagentnet/decide secureagentnet/integrations \
	secureagentnet/monitoring secureagentnet/cloud

typecheck:            ## advisory: type-check the whole package (does not gate)
	mypy secureagentnet/

typecheck-strict:     ## gating: the enforced core must be mypy-clean
	mypy --follow-imports=silent $(MYPY_ENFORCED)

doctor:
	secureagentnet doctor

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete
	rm -rf .pytest_cache .mypy_cache *.egg-info build dist
	rm -rf ~/.secureagentnet
