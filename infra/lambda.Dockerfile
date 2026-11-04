# The Lambda image: runtime dependencies, the package, and the model bundle (copied into build/bundle by
# `make deploy-image`, or fetched from the private bucket by the CI workflow). Built for arm64 (Graviton). Build from the repo root:
#   docker build --platform linux/arm64 -f infra/lambda.Dockerfile -t phish-triage .
FROM public.ecr.aws/lambda/python:3.12

COPY build/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm /tmp/requirements.txt

COPY src/phish_triage ${LAMBDA_TASK_ROOT}/phish_triage
COPY build/bundle /opt/bundle
# The smoke check's two hand-made test emails (service/smoke.py), and a second bundle for shadow mode when the image
# was built with SHADOW=<bundle version> (otherwise the folder holds only an empty marker file).
COPY build/smoke /opt/smoke
COPY build/shadow /opt/shadow

ENV PHISH_BUNDLE_DIR=/opt/bundle
CMD ["phish_triage.service.lambda_handler.handler"]
