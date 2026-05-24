# Workflow

## Install (editable dev)
```bash
pip install -e .
```
Uses `venv/bin/pip` if available. Entry points: `secureagentnet`, `san`.

## Verify
```bash
secureagentnet doctor
```

## Run tests
```bash
pytest tests/unit/ tests/red_team/ -v
```

## Run red team evaluation
```bash
python scripts/run_red_team.py
```

## Start server (with dashboard)
```bash
secureagentnet server start
```
