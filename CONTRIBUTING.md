# Contributing to VulnPilot

Thank you for your interest in contributing!

## Development Setup

```bash
git clone https://github.com/sainivedhh/VulnPilot.git
cd VulnPilot
python -m venv .venv
.venv\Scripts\activate      # Windows
pip install -r requirements.txt
pip install -e .
pip install pytest pytest-cov hypothesis ruff mypy
```

## Running Tests

```bash
PYTHONPATH=src pytest --cov=src --cov-fail-under=85
```

## Linting

```bash
python -m ruff check src/
python -m ruff format src/
```

## Pull Request Guidelines

1. All tests must pass and coverage must stay ≥ 85%.
2. Run `ruff check` before submitting — zero errors required.
3. Add tests for any new deterministic behaviour.
4. Never commit secrets, API keys, or credentials.
5. Security-related changes must update `docs/THREAT_MODEL.md` or `docs/AI_SECURITY.md`.

## Commit Style

Use conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `chore:`.
