.PHONY: test lint typecheck scan run update-intel help

PYTHONPATH := src

help:
	@echo "VulnPilot - Available targets:"
	@echo "  make test         Run tests with coverage gate (>=85%)"
	@echo "  make lint         Run ruff linting"
	@echo "  make typecheck    Run mypy strict type checking"
	@echo "  make scan         Scan sample fixture with VulnPilot"
	@echo "  make run          Start the FastAPI server locally"
	@echo "  make update-intel Refresh KEV and EPSS intel data"

test:
	PYTHONPATH=$(PYTHONPATH) pytest --cov=src --cov-fail-under=85 -v

lint:
	python -m ruff check src/
	python -m ruff format --check src/

typecheck:
	python -m mypy src/ --ignore-missing-imports

scan:
	PYTHONPATH=$(PYTHONPATH) vulnpilot scan tests/fixtures/trivy_sample.json \
		--policy-file policies/pipeline-policy.yaml \
		--format table

run:
	PYTHONPATH=$(PYTHONPATH) vulnpilot serve

update-intel:
	PYTHONPATH=$(PYTHONPATH) vulnpilot update-intel
