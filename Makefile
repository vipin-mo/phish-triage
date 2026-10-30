# phish-triage developer entry points. Run `make help`.
SHELL := /bin/bash
.DEFAULT_GOAL := help

.PHONY: help setup lint format test check-data check

help:  ## list targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

setup:  ## create .venv (Python 3.12), install dev deps, install git hooks
	uv sync
	uv run pre-commit install

lint:  ## ruff lint + format check
	uv run ruff check .
	uv run ruff format --check .

format:  ## auto-fix lint and formatting
	uv run ruff check --fix .
	uv run ruff format .

test:  ## unit tests
	uv run pytest

check-data:  ## fail if any tracked file looks like raw data
	uv run python scripts/check_no_raw_data.py

check: lint check-data test  ## everything CI runs
