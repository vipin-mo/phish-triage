# phish-triage

[![CI](https://github.com/vipin-mo/phish-triage/actions/workflows/ci.yml/badge.svg)](https://github.com/vipin-mo/phish-triage/actions/workflows/ci.yml)

> **Status: in progress.** Started October 2026. Nothing below is a result yet; numbers will be added
> only once they are measured.

phish-triage scores emails for phishing and explains why.

It grew out of my course project, where a simple model scored about 98% precision and recall, but its
explanations showed it was leaning on dataset artifacts: names like `enron` and years like `2004`, not
phishing signals. This project measures how much those artifacts and duplicate emails inflated that
score, and is built so the evaluation can't be fooled the same way:

- **Evaluation that can't cheat:** duplicates removed, a dataset-leakage audit, tests on a different
  source and on newer phishing, and recall reported at a fixed 1% false-alarm rate.
- **A three-stage cascade:** a fast linear model handles most emails, a fine-tuned DistilBERT handles
  the uncertain ones, and an LLM sees only the hardest. Measured: how much LLM is actually needed.
- **A safe LLM step:** grounded, schema-checked output that can raise risk but never lower it, tested
  against prompt injection hidden inside phishing emails.
- **Sender checks:** SPF, DKIM and DMARC results from the receiving mail provider, look-alike domains,
  and mismatched display names, From and Reply-To addresses.
- **Real use, serverless:** a Gmail sidebar add-on, AWS Lambda + SQS + DynamoDB via Terraform, and
  canary rollout of new models.

## Progress

- [x] **Phase 0** — repo, CI, [threat model](docs/THREAT_MODEL.md)
- [ ] **Phase 1** — data you can trust: [sources and data card](docs/DATA.md), de-duplication, leakage audit, splits
- [ ] **Phase 2** — features and baseline models, metrics module
- [ ] **Phase 3** — DistilBERT (ONNX int8), LLM comparison, cascade
- [ ] **Phase 4** — grounded LLM analyst step, prompt-injection tests, CI eval gate
- [ ] **Phase 5** — serverless AWS deployment (Terraform, OIDC CI/CD)
- [ ] **Phase 6** — Gmail add-on, feedback loop, canary, drift check
- [ ] **Phase 7** — load test, robustness report, write-up

## Development

Requires [uv](https://docs.astral.sh/uv/) and Python 3.12.

```bash
make setup   # create .venv, install dev deps, install git hooks
make check   # lint, raw-data guard, tests (what CI runs)
```

Raw email datasets are never committed. A pre-commit hook and a CI check block `.eml`/`.mbox` files and
anything under `data/`. Instead, `make data` downloads every source, checks it against pinned checksums,
and parses it into one unified record format (see [docs/DATA.md](docs/DATA.md)).

## License

MIT. Datasets keep their own licenses, documented in [docs/DATA.md](docs/DATA.md).
