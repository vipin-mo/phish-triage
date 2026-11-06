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
  # Every role the deploy role creates must carry this boundary (infra/service, `ci_role_boundary`).
  boundary_arn = "arn:aws:iam::${local.account}:policy/phish-triage-svc-boundary"
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
    # Only this workflow, from main: another workflow, or one on a branch, that names the environment gets nothing,
    # whatever the environment's branch rules in GitHub say.
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:job_workflow_ref"
      values   = ["${var.github_repo}/.github/workflows/deploy.yml@refs/heads/main"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:ref"
      values   = ["refs/heads/main"]
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
  # ReadOnlyAccess reads data as well as settings; a plan needs only the settings. Denied: the model and the
  # emails sent for retraining, the tables' items, the Anthropic key, the image (it holds the model) and the logs.
  statement {
    effect    = "Deny"
    actions   = ["s3:GetObject", "s3:GetObjectVersion"]
    resources = ["${aws_s3_bucket.models.arn}/*", "arn:aws:s3:::phish-triage-retraining-*/*"]
  }
  statement {
    effect = "Deny"
    actions = [
      "dynamodb:GetItem", "dynamodb:BatchGetItem", "dynamodb:Query", "dynamodb:Scan", "dynamodb:PartiQLSelect",
      "dynamodb:ExportTableToPointInTime", "dynamodb:GetRecords",
    ]
    resources = ["arn:aws:dynamodb:${var.region}:${local.account}:table/phish-triage-*"]
  }
  statement {
    effect    = "Deny"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = ["*"]
  }
  statement {
    effect    = "Deny"
    actions   = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
    resources = [aws_ecr_repository.service.arn]
  }
  statement {
    effect = "Deny"
    actions = [
      "logs:GetLogEvents", "logs:FilterLogEvents", "logs:StartQuery", "logs:GetQueryResults", "logs:StartLiveTail",
      "logs:GetLogRecord", "sqs:ReceiveMessage",
    ]
    resources = ["*"]
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
    sid       = "PushImage" # no repository policy: it could share the image, which holds the model, with another account
    actions   = ["ecr:BatchCheckLayerAvailability", "ecr:CompleteLayerUpload", "ecr:InitiateLayerUpload", "ecr:PutImage", "ecr:UploadLayerPart", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:DescribeImages", "ecr:DescribeRepositories", "ecr:ListTagsForResource", "ecr:GetRepositoryPolicy"]
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
      "lambda:Get*", "lambda:List*", "dynamodb:Describe*", "dynamodb:List*", "apigateway:GET", "logs:Describe*",
      "logs:List*", "cloudwatch:Describe*", "cloudwatch:Get*", "cloudwatch:List*", "sns:Get*", "sns:List*", "iam:Get*",
      "iam:List*", "sts:GetCallerIdentity", "budgets:View*", "events:Describe*", "events:List*", "codedeploy:Get*",
      "codedeploy:List*", "codedeploy:BatchGet*", "secretsmanager:DescribeSecret", "secretsmanager:GetResourcePolicy",
      "secretsmanager:ListSecrets",
    ]
    resources = ["*"]
  }
  statement {
    sid     = "Functions"
    actions = ["lambda:*"]
    resources = [
      "arn:aws:lambda:${var.region}:${local.account}:function:phish-triage-*",
      "arn:aws:lambda:${var.region}:${local.account}:function:CodeDeployHook_phish-triage*",
    ]
  }
  # No public function URL beside the API (it would skip the API's throttling), and a permission to invoke a function
  # only for the API and the schedules.
  statement {
    sid       = "NoFunctionUrls"
    effect    = "Deny"
    actions   = ["lambda:CreateFunctionUrlConfig", "lambda:UpdateFunctionUrlConfig"]
    resources = ["*"]
  }
  statement {
    sid       = "InvokePermissionsForTheServiceOnly"
    effect    = "Deny"
    actions   = ["lambda:AddPermission"]
    resources = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "lambda:Principal"
      values   = ["apigateway.amazonaws.com", "events.amazonaws.com"]
    }
  }
  statement {
    sid       = "Tables"
    actions   = ["dynamodb:CreateTable", "dynamodb:DeleteTable", "dynamodb:UpdateTable", "dynamodb:UpdateTimeToLive", "dynamodb:TagResource", "dynamodb:UntagResource", "dynamodb:UpdateContinuousBackups"]
    resources = ["arn:aws:dynamodb:${var.region}:${local.account}:table/phish-triage-*"]
  }
  statement {
    sid       = "Api" # it can still point the API at another target: approving the deploy is the check on that
    actions   = ["apigateway:POST", "apigateway:PUT", "apigateway:PATCH", "apigateway:DELETE", "apigateway:TagResource"]
    resources = ["arn:aws:apigateway:${var.region}::/apis", "arn:aws:apigateway:${var.region}::/apis/*", "arn:aws:apigateway:${var.region}::/tags/*"]
  }
  statement {
    sid     = "LogGroups"
    actions = ["logs:CreateLogGroup", "logs:DeleteLogGroup", "logs:PutRetentionPolicy", "logs:TagResource", "logs:UntagResource", "logs:TagLogGroup"]
    resources = [
      "arn:aws:logs:${var.region}:${local.account}:log-group:/aws/lambda/phish-triage-*",
      "arn:aws:logs:${var.region}:${local.account}:log-group:/aws/lambda/CodeDeployHook_phish-triage*",
      "arn:aws:logs:${var.region}:${local.account}:log-group:/aws/apigateway/phish-triage*",
    ]
  }
  statement {
    sid       = "ApiAccessLogs" # these take no resource
    actions   = ["logs:CreateLogDelivery", "logs:GetLogDelivery", "logs:UpdateLogDelivery", "logs:DeleteLogDelivery", "logs:ListLogDeliveries", "logs:DescribeResourcePolicies"]
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
    sid       = "Schedules"
    actions   = ["events:PutRule", "events:DeleteRule", "events:PutTargets", "events:RemoveTargets", "events:TagResource", "events:UntagResource", "events:EnableRule", "events:DisableRule"]
    resources = ["arn:aws:events:${var.region}:${local.account}:rule/phish-triage-*"]
  }
  statement {
    sid       = "SecretShell" # the secret's settings; its value is put there from my laptop and denied below
    actions   = ["secretsmanager:CreateSecret", "secretsmanager:DeleteSecret", "secretsmanager:UpdateSecret", "secretsmanager:TagResource", "secretsmanager:UntagResource"]
    resources = ["arn:aws:secretsmanager:${var.region}:${local.account}:secret:phish-triage/*"]
  }
  statement {
    sid       = "NoSecretValue"
    effect    = "Deny"
    actions   = ["secretsmanager:GetSecretValue", "secretsmanager:BatchGetSecretValue", "secretsmanager:PutSecretValue"]
    resources = ["*"]
  }
  statement {
    sid = "RetrainingBucket" # the bucket's settings only: the emails in it are denied below
    actions = [
      "s3:CreateBucket", "s3:DeleteBucket", "s3:ListBucket", "s3:GetBucket*", "s3:GetLifecycleConfiguration",
      "s3:GetEncryptionConfiguration", "s3:GetReplicationConfiguration", "s3:GetAccelerateConfiguration",
      "s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:PutBucketPublicAccessBlock", "s3:PutLifecycleConfiguration",
      "s3:PutEncryptionConfiguration", "s3:PutBucketTagging",
    ]
    resources = ["arn:aws:s3:::phish-triage-retraining-${local.account}"]
  }
  statement {
    sid       = "NoRetrainingEmails"
    effect    = "Deny"
    actions   = ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject", "s3:DeleteObject"]
    resources = ["arn:aws:s3:::phish-triage-retraining-${local.account}/*"]
  }
  statement {
    sid = "Canary"
    actions = [
      "codedeploy:CreateApplication", "codedeploy:DeleteApplication", "codedeploy:CreateDeploymentGroup",
      "codedeploy:UpdateDeploymentGroup", "codedeploy:DeleteDeploymentGroup", "codedeploy:CreateDeployment",
      "codedeploy:StopDeployment", "codedeploy:TagResource", "codedeploy:UntagResource",
    ]
    resources = [
      "arn:aws:codedeploy:${var.region}:${local.account}:application:phish-triage",
      "arn:aws:codedeploy:${var.region}:${local.account}:deploymentgroup:phish-triage/*",
      "arn:aws:codedeploy:${var.region}:${local.account}:deploymentconfig:*",
    ]
  }
  # The function roles: CI changes only the roles a laptop deploy made. It can't make one or change who may assume
  # one (an outside account could then), and a policy it writes or attaches only counts on a role that carries the
  # boundary, which caps what any policy on it can grant; it can't remove the boundary, and it can attach only the one
  # AWS policy CodeDeploy needs.
  statement {
    sid       = "FunctionRolePolicies"
    actions   = ["iam:PutRolePolicy", "iam:PutRolePermissionsBoundary"]
    resources = ["arn:aws:iam::${local.account}:role/phish-triage-svc-*"]
    condition {
      test     = "StringEquals"
      variable = "iam:PermissionsBoundary"
      values   = [local.boundary_arn]
    }
  }
  statement {
    sid       = "FunctionRolesAttach"
    actions   = ["iam:AttachRolePolicy"]
    resources = ["arn:aws:iam::${local.account}:role/phish-triage-svc-*"]
    condition {
      test     = "StringEquals"
      variable = "iam:PermissionsBoundary"
      values   = [local.boundary_arn]
    }
    condition {
      test     = "ArnEquals"
      variable = "iam:PolicyARN"
      values   = ["arn:aws:iam::aws:policy/service-role/AWSCodeDeployRoleForLambda"]
    }
  }
  statement {
    sid       = "FunctionRolesChange"
    actions   = ["iam:DeleteRolePolicy", "iam:DetachRolePolicy", "iam:TagRole", "iam:UntagRole"]
    resources = ["arn:aws:iam::${local.account}:role/phish-triage-svc-*"]
  }
  statement {
    sid       = "KeepRolesAndTheBoundary"
    effect    = "Deny"
    actions   = ["iam:CreateRole", "iam:DeleteRole", "iam:UpdateAssumeRolePolicy", "iam:DeleteRolePermissionsBoundary", "iam:CreatePolicyVersion", "iam:DeletePolicy", "iam:SetDefaultPolicyVersion"]
    resources = ["arn:aws:iam::${local.account}:role/*", local.boundary_arn]
  }
  statement {
    sid       = "PassFunctionRoles"
    actions   = ["iam:PassRole"]
    resources = ["arn:aws:iam::${local.account}:role/phish-triage-svc-*"]
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["lambda.amazonaws.com", "codedeploy.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "deploy" {
  count  = var.github_oidc ? 1 : 0
  role   = aws_iam_role.deploy[0].id
  policy = data.aws_iam_policy_document.deploy.json
}

# The most any function role made by the deploy role can do: the service's own tables, logs, secret, buckets, alarms
# and functions, and nothing in IAM or STS. The roles' own policies are narrower; this caps what a changed one could
# grant.
data "aws_iam_policy_document" "boundary" {
  statement {
    actions = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = [
      "arn:aws:logs:${var.region}:${local.account}:log-group:/aws/lambda/phish-triage-*",
      "arn:aws:logs:${var.region}:${local.account}:log-group:/aws/lambda/CodeDeployHook_phish-triage*",
    ]
  }
  # Per table, what the service does with it (infra/service): keys are read, verdicts read, written and scanned by the
  # drift check, feedback added, the rate counters updated.
  statement {
    actions   = ["dynamodb:GetItem"]
    resources = ["arn:aws:dynamodb:${var.region}:${local.account}:table/phish-triage-keys"]
  }
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Scan"]
    resources = ["arn:aws:dynamodb:${var.region}:${local.account}:table/phish-triage-verdicts"]
  }
  statement {
    actions   = ["dynamodb:PutItem"]
    resources = ["arn:aws:dynamodb:${var.region}:${local.account}:table/phish-triage-feedback"]
  }
  statement {
    actions   = ["dynamodb:UpdateItem"]
    resources = ["arn:aws:dynamodb:${var.region}:${local.account}:table/phish-triage-rate"]
  }
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = ["arn:aws:secretsmanager:${var.region}:${local.account}:secret:phish-triage/*"]
  }
  statement {
    actions   = ["kms:Decrypt"] # the secret's key, only through Secrets Manager
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${var.region}.amazonaws.com"]
    }
  }
  statement {
    actions   = ["s3:PutObject"] # write only: no role made by CI can read an email sent for retraining
    resources = ["arn:aws:s3:::phish-triage-retraining-${local.account}/*"]
  }
  statement {
    actions = ["lambda:InvokeFunction", "lambda:GetAlias", "lambda:UpdateAlias", "lambda:GetProvisionedConcurrencyConfig"]
    resources = [
      "arn:aws:lambda:${var.region}:${local.account}:function:phish-triage-*",
      "arn:aws:lambda:${var.region}:${local.account}:function:CodeDeployHook_phish-triage*",
    ]
  }
  statement {
    actions   = ["codedeploy:GetDeployment", "codedeploy:PutLifecycleEventHookExecutionStatus", "cloudwatch:PutMetricData", "cloudwatch:DescribeAlarms"]
    resources = ["*"]
  }
  statement {
    actions   = ["sns:Publish"]
    resources = ["arn:aws:sns:${var.region}:${local.account}:phish-triage-*"]
  }
}

resource "aws_iam_policy" "boundary" {
  count  = var.github_oidc ? 1 : 0
  name   = "phish-triage-svc-boundary"
  policy = data.aws_iam_policy_document.boundary.json
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
    # Test images (dev-*) go first, so they can't push out the running one; merged commits keep the last 10 (about
    # 6 GB, $0.60 a month), enough to roll back.
    rules = [
      {
        rulePriority = 1
        description  = "keep the last 3 test images"
        selection    = { tagStatus = "tagged", tagPatternList = ["dev-*"], countType = "imageCountMoreThan", countNumber = 3 }
        action       = { type = "expire" }
      },
      {
        rulePriority = 2
        description  = "keep the last 10 images"
        selection    = { tagStatus = "any", countType = "imageCountMoreThan", countNumber = 10 }
        action       = { type = "expire" }
      },
    ]
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
