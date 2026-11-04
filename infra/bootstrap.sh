#!/usr/bin/env bash
# Create the S3 bucket that holds Terraform's state, once per AWS account. Run from the repo root with the
# phish-triage profile: AWS_PROFILE=phish-triage infra/bootstrap.sh
# Safe to run again: it only creates what is missing. Everything else is in Terraform (infra/foundation, infra/service).
set -euo pipefail
REGION=us-east-2
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
BUCKET="phish-triage-tfstate-${ACCOUNT}"
if ! aws s3api head-bucket --bucket "$BUCKET" 2>/dev/null; then
  aws s3api create-bucket --bucket "$BUCKET" --region "$REGION" \
    --create-bucket-configuration LocationConstraint="$REGION"
fi
aws s3api put-public-access-block --bucket "$BUCKET" --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws s3api put-bucket-versioning --bucket "$BUCKET" --versioning-configuration Status=Enabled
aws s3api put-bucket-encryption --bucket "$BUCKET" --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"},"BucketKeyEnabled":true}]}'
aws s3api put-bucket-tagging --bucket "$BUCKET" --tagging 'TagSet=[{Key=Project,Value=phish-triage}]'
echo "state bucket ready: $BUCKET"
