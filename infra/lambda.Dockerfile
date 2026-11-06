# The Lambda image: runtime dependencies, the package, and the model bundle (copied into build/bundle by
# `make deploy-image`, or fetched from the private bucket by the CI workflow). Built for arm64 (Graviton). Build from the repo root:
#   docker build --platform linux/arm64 -f infra/lambda.Dockerfile -t phish-triage .
# Pinned by digest (the multi-arch index of 3.12 on 2026-11-05), so a rebuild gets the same base; to take AWS's
# patches, look up the new digest of the 3.12 tag and change it here.
FROM public.ecr.aws/lambda/python:3.12@sha256:238f6bfd2c1c188aff3955c2f7ceb767fe9da1b3597d84264426a11690fcf2d7

COPY build/requirements.txt /tmp/requirements.txt
# Every requirement carries its hash (uv.lock's): a package changed on the index since it was locked isn't installed.
RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements.txt && rm /tmp/requirements.txt

COPY src/phish_triage ${LAMBDA_TASK_ROOT}/phish_triage
COPY build/bundle /opt/bundle
# The smoke check's two hand-made test emails (service/smoke.py), and a second bundle for shadow mode when the image
# was built with SHADOW=<bundle version> (otherwise the folder holds only an empty marker file).
COPY build/smoke /opt/smoke
COPY build/shadow /opt/shadow

ENV PHISH_BUNDLE_DIR=/opt/bundle
CMD ["phish_triage.service.lambda_handler.handler"]
