# What deploys need before they can run: the image registry and the private model bucket, and, where the account
# allows it, the GitHub sign-in (OIDC) and the two CI roles. Applied once from my laptop with the phish-triage
# profile (make tf-foundation-plan / -apply); everything that runs is in infra/service.
#
# The AWS Free plan denies `iam:*Provider*` to every account (a service control policy AWS manages; the Paid plan
# too, until advanced features are activated), so GitHub can't sign in without stored keys. On this account
# `github_oidc` is false and I deploy from my laptop with MFA (make deploy-*). On an account that allows OIDC, setting
# it to true creates the provider and roles that .github/workflows/deploy.yml uses.

terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.71" }
  }
  backend "s3" {
    key          = "foundation.tfstate"
    region       = "us-east-2"
    use_lockfile = true
    encrypt      = true
  }
}

provider "aws" {
  region = var.region
  default_tags { tags = { Project = "phish-triage" } }
}

variable "region" {
  type    = string
  default = "us-east-2"
}

variable "github_oidc" {
  description = "Create the GitHub OIDC provider and CI roles (not allowed on the AWS Free plan)"
  type        = bool
  default     = false
}

variable "github_repo" {
  type    = string
  default = "vipin-mo/phish-triage"
}

data "aws_caller_identity" "me" {}

locals {
  account     = data.aws_caller_identity.me.account_id
  state_arn   = "arn:aws:s3:::phish-triage-tfstate-${local.account}"
  models_name = "phish-triage-models-${local.account}"
}

# GitHub Actions signs in with a short-lived token instead of stored keys.
resource "aws_iam_openid_connect_provider" "github" {
  count          = var.github_oidc ? 1 : 0
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
}

data "aws_iam_policy_document" "trust_plan" {
  count = var.github_oidc ? 1 : 0
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github[0].arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repo}:pull_request"]
    }
  }
}

# Only a job in the `production` environment, which waits for my approval, can deploy.
data "aws_iam_policy_document" "trust_deploy" {
  count = var.github_oidc ? 1 : 0
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github[0].arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repo}:environment:production"]
    }
  }
}

# Plan on pull requests: read everything Terraform needs, but none of the data (the model, the verdicts).
resource "aws_iam_role" "plan" {
  count                = var.github_oidc ? 1 : 0
  name                 = "phish-triage-ci-plan"
  assume_role_policy   = data.aws_iam_policy_document.trust_plan[0].json
  max_session_duration = 3600
}

resource "aws_iam_role_policy_attachment" "plan_read" {
  count      = var.github_oidc ? 1 : 0
  role       = aws_iam_role.plan[0].name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

data "aws_iam_policy_document" "plan_no_data" {
  statement {
    effect    = "Deny"
    actions   = ["s3:GetObject", "s3:GetObjectVersion"]
    resources = ["${aws_s3_bucket.models.arn}/*"]
  }
  statement {
    effect    = "Deny"
    actions   = ["dynamodb:GetItem", "dynamodb:BatchGetItem", "dynamodb:Query", "dynamodb:Scan"]
    resources = ["arn:aws:dynamodb:${var.region}:${local.account}:table/phish-triage-*"]
  }
}

resource "aws_iam_role_policy" "plan_no_data" {
  count  = var.github_oidc ? 1 : 0
  role   = aws_iam_role.plan[0].id
  policy = data.aws_iam_policy_document.plan_no_data.json
}

# Deploy: build and push the image, and apply infra/service. Writes are limited to phish-triage resources.
resource "aws_iam_role" "deploy" {
  count                = var.github_oidc ? 1 : 0
  name                 = "phish-triage-ci-deploy"
  assume_role_policy   = data.aws_iam_policy_document.trust_deploy[0].json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "deploy" {
  statement {
    sid       = "State"
    actions   = ["s3:ListBucket", "s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = [local.state_arn, "${local.state_arn}/*"]
  }
  statement {
    sid       = "Bundle"
    actions   = ["s3:ListBucket", "s3:GetObject"]
    resources = [aws_s3_bucket.models.arn, "${aws_s3_bucket.models.arn}/*"]
  }
  statement {
    sid       = "PushImage"
    actions   = ["ecr:BatchCheckLayerAvailability", "ecr:CompleteLayerUpload", "ecr:InitiateLayerUpload", "ecr:PutImage", "ecr:UploadLayerPart", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:DescribeImages", "ecr:DescribeRepositories", "ecr:ListTagsForResource", "ecr:GetRepositoryPolicy", "ecr:SetRepositoryPolicy"]
    resources = [aws_ecr_repository.service.arn]
  }
  statement {
    sid       = "EcrLogin"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    sid = "Read"
    actions = [
      "lambda:Get*", "lambda:List*", "dynamodb:Describe*", "dynamodb:List*", "sqs:Get*", "sqs:List*",
      "apigateway:GET", "logs:Describe*", "logs:List*", "cloudwatch:Describe*", "cloudwatch:Get*", "cloudwatch:List*",
      "sns:Get*", "sns:List*", "iam:Get*", "iam:List*", "sts:GetCallerIdentity", "budgets:View*",
    ]
    resources = ["*"]
  }
  statement {
    sid       = "Functions"
    actions   = ["lambda:*"]
    resources = ["arn:aws:lambda:${var.region}:${local.account}:function:phish-triage-*"]
  }
  statement {
    sid       = "EventSourceMappings"
    actions   = ["lambda:CreateEventSourceMapping", "lambda:UpdateEventSourceMapping", "lambda:DeleteEventSourceMapping", "lambda:TagResource", "lambda:UntagResource"]
    resources = ["*"]
    condition {
      test     = "StringLike"
      variable = "lambda:FunctionArn"
      values   = ["arn:aws:lambda:${var.region}:${local.account}:function:phish-triage-*"]
    }
  }
  statement {
    sid       = "Tables"
    actions   = ["dynamodb:CreateTable", "dynamodb:DeleteTable", "dynamodb:UpdateTable", "dynamodb:UpdateTimeToLive", "dynamodb:TagResource", "dynamodb:UntagResource", "dynamodb:UpdateContinuousBackups"]
    resources = ["arn:aws:dynamodb:${var.region}:${local.account}:table/phish-triage-*"]
  }
  statement {
    sid       = "Queues"
    actions   = ["sqs:CreateQueue", "sqs:DeleteQueue", "sqs:SetQueueAttributes", "sqs:TagQueue", "sqs:UntagQueue"]
    resources = ["arn:aws:sqs:${var.region}:${local.account}:phish-triage-*"]
  }
  statement {
    sid       = "Api"
    actions   = ["apigateway:POST", "apigateway:PUT", "apigateway:PATCH", "apigateway:DELETE", "apigateway:TagResource"]
    resources = ["arn:aws:apigateway:${var.region}::/apis", "arn:aws:apigateway:${var.region}::/apis/*", "arn:aws:apigateway:${var.region}::/tags/*"]
  }
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogGroup", "logs:DeleteLogGroup", "logs:PutRetentionPolicy", "logs:TagResource", "logs:UntagResource", "logs:TagLogGroup", "logs:CreateLogDelivery", "logs:UpdateLogDelivery", "logs:DeleteLogDelivery", "logs:PutResourcePolicy", "logs:DescribeResourcePolicies"]
    resources = ["*"]
  }
  statement {
    sid       = "Alarms"
    actions   = ["cloudwatch:PutMetricAlarm", "cloudwatch:DeleteAlarms", "cloudwatch:TagResource", "cloudwatch:UntagResource", "cloudwatch:PutDashboard", "cloudwatch:DeleteDashboards"]
    resources = ["arn:aws:cloudwatch:${var.region}:${local.account}:alarm:phish-triage-*", "arn:aws:cloudwatch::${local.account}:dashboard/phish-triage*"]
  }
  statement {
    sid       = "Topic"
    actions   = ["sns:CreateTopic", "sns:DeleteTopic", "sns:SetTopicAttributes", "sns:Subscribe", "sns:Unsubscribe", "sns:TagResource", "sns:UntagResource"]
    resources = ["arn:aws:sns:${var.region}:${local.account}:phish-triage-*"]
  }
  statement {
    sid       = "FunctionRoles"
    actions   = ["iam:CreateRole", "iam:DeleteRole", "iam:UpdateAssumeRolePolicy", "iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:AttachRolePolicy", "iam:DetachRolePolicy", "iam:TagRole", "iam:UntagRole"]
    resources = ["arn:aws:iam::${local.account}:role/phish-triage-svc-*"]
  }
  statement {
    sid       = "PassFunctionRoles"
    actions   = ["iam:PassRole"]
    resources = ["arn:aws:iam::${local.account}:role/phish-triage-svc-*"]
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "deploy" {
  count  = var.github_oidc ? 1 : 0
  role   = aws_iam_role.deploy[0].id
  policy = data.aws_iam_policy_document.deploy.json
}

# The image registry (private) and the model bucket (private, versioned). The model is trained partly on my
# inbox, so it is never public.
resource "aws_ecr_repository" "service" {
  name                 = "phish-triage"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration { scan_on_push = true }
  encryption_configuration { encryption_type = "AES256" }
}

resource "aws_ecr_lifecycle_policy" "service" {
  repository = aws_ecr_repository.service.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "keep the last 5 images"
      selection    = { tagStatus = "any", countType = "imageCountMoreThan", countNumber = 5 }
      action       = { type = "expire" }
    }]
  })
}

resource "aws_s3_bucket" "models" {
  bucket = local.models_name
}

resource "aws_s3_bucket_public_access_block" "models" {
  bucket                  = aws_s3_bucket.models.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "models" {
  bucket = aws_s3_bucket.models.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "models" {
  bucket = aws_s3_bucket.models.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
    bucket_key_enabled = true
  }
}

data "aws_iam_policy_document" "models_tls" {
  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.models.arn, "${aws_s3_bucket.models.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "models" {
  bucket = aws_s3_bucket.models.id
  policy = data.aws_iam_policy_document.models_tls.json
}

output "plan_role_arn" { value = one(aws_iam_role.plan[*].arn) }
output "deploy_role_arn" { value = one(aws_iam_role.deploy[*].arn) }
output "ecr_repository_url" { value = aws_ecr_repository.service.repository_url }
output "models_bucket" { value = aws_s3_bucket.models.bucket }
