# phish-triage developer entry points. Run `make help`.
SHELL := /bin/bash
.DEFAULT_GOAL := help

.PHONY: help setup lint format test check-data check data data-download data-build data-prepare data-splits audit

help:  ## list targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

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

data: data-download data-build data-prepare data-splits  ## download, parse, mask, de-duplicate and split (fixed seeds)

data-download:  ## download raw datasets into data/raw/ and verify checksums
	uv run python -m phish_triage.data.download

data-build:  ## parse data/raw/ into data/interim/records.jsonl.gz (+ summary.json)
	uv run python -m phish_triage.data.build

data-prepare:  ## mask source fingerprints and remove duplicates (data/interim/masked.jsonl.gz, dedup.json)
	uv run python -m phish_triage.data.prepare

data-splits:  ## build every split with fixed seeds (data/splits/)
	uv run python -m phish_triage.data.splits

audit:  ## leakage audit on the splits (reports/leakage_audit.md)
	uv run python -m phish_triage.data.audit
