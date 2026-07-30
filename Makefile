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

typecheck:
	mypy secureagentnet/

doctor:
	secureagentnet doctor

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete
	rm -rf .pytest_cache .mypy_cache *.egg-info build dist
	rm -rf ~/.secureagentnet
