# phish-triage developer entry points. Run `make help`.
SHELL := /bin/bash
.DEFAULT_GOAL := help

.PHONY: help setup lint format test check-data check data data-download data-build data-prepare data-splits audit eval-baselines eval-course train-transformer eval eval-analyst eval-injection eval-test-inbox data-inbox train-with-inbox eval-with-inbox privacymail-counts private-collectors data-privacymail train-with-newsletters eval-privacymail gate bundle serve aws-bootstrap tf-foundation-plan tf-foundation-apply upload-bundle api-key deploy-image deploy-plan deploy-apply

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

eval-baselines:  ## train and evaluate the baseline models on every split (reports/baselines.md)
	uv run python -m phish_triage.evaluation.baselines

eval-course:  ## reproduce the course project's score and test how much survives (reports/course_reproduction.md)
	uv run python -m phish_triage.evaluation.course

train-transformer:  ## fine-tune DistilBERT on every split (+ head/tail variant), export ONNX int8 (~2 h on an M5)
	uv run --group train python -m phish_triage.models.train_transformer --strategy head
	uv run --group train python -m phish_triage.models.train_transformer random by_time --strategy head_tail

eval:  ## rebuild docs/RESULTS.md from saved predictions (no training, no API calls)
	uv run python -m phish_triage.evaluation.results

eval-analyst:  ## analyst step on 200 emails + my rating sheet (Claude, costs money: CONFIRM=--confirm)
	uv run --group train python -m phish_triage.evaluation.analyst_eval $(if $(CONFIRM),run $(CONFIRM),plan)

eval-injection:  ## prompt-injection rounds 1 and 2 (Claude, costs money: CONFIRM=--confirm)
	uv run --group train python -m phish_triage.evaluation.injection $(if $(CONFIRM),run $(CONFIRM),plan)
	uv run --group train python -m phish_triage.evaluation.injection $(if $(CONFIRM),run $(CONFIRM),plan) --round 2

data-inbox:  ## mask my private test inbox and build the `with_inbox` split (stays in data/private/)
	uv run python -m phish_triage.data.inbox

train-with-inbox:  ## fine-tune DistilBERT on the private `with_inbox` split and export it (~30 min on an M5)
	uv run --group train python -m phish_triage.models.train_transformer with_inbox

privacymail-counts:  ## count-only look at the PrivacyMail newsletter zip in data/private/privacymail/
	uv run python -m phish_triage.data.privacymail

private-collectors:  ## write the private sources' collection names to mask (data/private, counts printed only)
	uv run python -m phish_triage.data.privacymail --collectors

data-privacymail:  ## build the private `with_newsletters` split (with_inbox + PrivacyMail, split by website)
	uv run python -m phish_triage.data.privacymail --build

train-with-newsletters:  ## fine-tune DistilBERT on `with_newsletters` and export it (~1 h on an M5)
	uv run --group train python -m phish_triage.models.train_transformer with_newsletters

eval-privacymail:  ## false alarms of the with_inbox bundle on PrivacyMail newsletters (reports/privacymail.md)
	uv run python -m phish_triage.evaluation.privacymail

eval-with-inbox:  ## before/after: models trained without and with part of my inbox (local only, aggregates only)
	uv run --group train python -m phish_triage.evaluation.with_inbox

eval-test-inbox:  ## false alarms on my private test inbox (local models only, aggregates only; never sent to an LLM)
	uv run --group train python -m phish_triage.evaluation.test_inbox

bundle:  ## export the deployable model bundle (with_newsletters) and check it against reports/with_inbox.md (reports/bundle.md)
	uv run python -m phish_triage.service.bundle

serve:  ## run the API locally on the latest bundle (prints a one-run API key)
	uv run uvicorn --factory phish_triage.service.api:local_app --port 8000

gate:  ## measure the eval gate from local results -> reports/gate.json (CI runs the free --check)
	uv run python -m phish_triage.evaluation.gate

# --- AWS (Phase 5). Sign in first in your own terminal: aws sts get-caller-identity --profile phish-triage ---
AWS_PROFILE_NAME := phish-triage
AWS_ENV = eval "$$(aws configure export-credentials --profile $(AWS_PROFILE_NAME) --format env)" && export AWS_REGION=us-east-2 AWS_DEFAULT_REGION=us-east-2
ACCOUNT = $$(aws sts get-caller-identity --profile $(AWS_PROFILE_NAME) --query Account --output text)

aws-bootstrap:  ## create the Terraform state bucket (once per account)
	AWS_PROFILE=$(AWS_PROFILE_NAME) infra/bootstrap.sh

tf-foundation-plan:  ## plan infra/foundation (OIDC, CI roles, registry, model bucket)
	$(AWS_ENV) && terraform -chdir=infra/foundation init -input=false -backend-config="bucket=phish-triage-tfstate-$(ACCOUNT)" && terraform -chdir=infra/foundation plan -input=false -out=foundation.tfplan

tf-foundation-apply:  ## apply the saved foundation plan
	$(AWS_ENV) && terraform -chdir=infra/foundation apply -input=false foundation.tfplan

upload-bundle:  ## copy the bundle named in infra/bundle-version to the private model bucket
	aws s3 sync --profile $(AWS_PROFILE_NAME) --only-show-errors "artifacts/bundle/$$(cat infra/bundle-version)/" "s3://phish-triage-models-$(ACCOUNT)/bundles/$$(cat infra/bundle-version)/"

api-key:  ## create an API key for the deployed service (OWNER=name)
	$(AWS_ENV) && uv run python -m phish_triage.service.keys create --owner $(OWNER)

# Deploy from the laptop (the Free plan blocks CI's OIDC sign-in). Docker Desktop must be running.
# make deploy-plan shows what will change; make deploy-apply applies exactly that plan and checks /v1/health.
REGISTRY = $(ACCOUNT).dkr.ecr.us-east-2.amazonaws.com
IMAGE_TAG = $$(git diff --quiet HEAD && git rev-parse HEAD || echo "dev-$$(git rev-parse --short HEAD)-$$(date +%Y%m%d%H%M%S)")

deploy-image:  ## build the arm64 Lambda image with the bundle and push it to the private registry
	mkdir -p build && rm -rf build/bundle && cp -R "artifacts/bundle/$$(cat infra/bundle-version)" build/bundle
	uv export --no-default-groups --group service --no-hashes --no-emit-project --format requirements-txt -q > build/requirements.txt
	tag=$(IMAGE_TAG) && echo "$$tag" > build/image-tag && \
	aws ecr get-login-password --profile $(AWS_PROFILE_NAME) --region us-east-2 | docker login --username AWS --password-stdin $(REGISTRY) && \
	docker buildx build --platform linux/arm64 --provenance=false --sbom=false -f infra/lambda.Dockerfile -t "$(REGISTRY)/phish-triage:$$tag" --push . && \
	echo "pushed phish-triage:$$tag"

deploy-plan:  ## plan infra/service for the image in build/image-tag (ALERT_EMAIL=... to email alarms)
	$(AWS_ENV) && terraform -chdir=infra/service init -input=false -backend-config="bucket=phish-triage-tfstate-$(ACCOUNT)" && \
	terraform -chdir=infra/service plan -input=false -out=service.tfplan -var "image_tag=$$(cat build/image-tag)" -var "alert_email=$(ALERT_EMAIL)"

deploy-apply:  ## apply the saved service plan, load the model once (warm-up), then check /v1/health
	$(AWS_ENV) && terraform -chdir=infra/service apply -input=false service.tfplan && \
	aws lambda wait function-updated-v2 --function-name phish-triage-scan && \
	aws lambda invoke --function-name phish-triage-scan --cli-binary-format raw-in-base64-out --cli-read-timeout 150 \
	  --payload '{"source": "aws.events"}' build/warm.json >/dev/null && echo "warm-up: $$(cat build/warm.json)" && \
	curl -fsS --retry 5 --retry-delay 10 --max-time 60 "$$(terraform -chdir=infra/service output -raw api_url)/v1/health" && echo
