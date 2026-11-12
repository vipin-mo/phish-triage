# infra/

Terraform for the AWS deployment, in us-east-2. I deploy from my laptop with a short MFA session; nothing here holds
keys or account details.

| Path | What it is |
|---|---|
| `bootstrap.sh` | Creates the S3 bucket for Terraform's state, once per account. |
| `foundation/` | What deploys need first: the image registry (ECR, keeping the last 10 images), the private model bucket, and the GitHub sign-in (OIDC) and CI roles, which stay off (`github_oidc = false`) because the AWS Free plan blocks the OIDC provider. Applied once (`make tf-foundation-plan`, then `make tf-foundation-apply`). |
| `service/` | Everything that runs: the scan function behind API Gateway, its DynamoDB tables, the CodeDeploy canary, the weekly drift check, the warm-up ping, alarms and the dashboard. |
| `lambda.Dockerfile` | The Lambda image (arm64): runtime dependencies, the package and the model bundle. |
| `bundle-version` | The model bundle the image ships. |
| `retraining-owners` | Which API key owners may send emails for retraining. |

A deploy is three commands:

1. `make deploy-image` builds the image with the bundle and pushes it.
2. `make deploy-plan` plans `service/` for that image, and I read the plan.
3. `make deploy-apply` applies it, runs the canary (a smoke check, then 10% of traffic for 10 minutes, rolled back
   on the error, 5xx and latency alarms), warms the new version and checks that the loaded model is the pinned one.

The smoke check also fails a version whose loaded model isn't the bundle in `bundle-version`, before any traffic
moves. `make rollback-check VERSION=<n>` deploys an older version on purpose: on 2026-11-12, version 8 (the previous
model) passed the smoke emails but was stopped by that check, CodeDeploy rolled it back and `live` stayed on version
9 ([reports/canary_rollback.md](../reports/canary_rollback.md)). The alarm-driven rollback during the 10% window
hasn't had to run: with one user the window often gets no scans, so the smoke check is what really tests a new
version, and the latency alarm needs 15 minutes of data, longer than the canary.
