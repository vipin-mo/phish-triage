# Everything that runs: the scan function behind API Gateway, its DynamoDB tables, the canary, the drift check,
# logs, alarms and a dashboard. Deployed from my laptop with `make deploy-plan` and
# `make deploy-apply` (the Free plan blocks the CI workflow's OIDC sign-in); the image tag names the build.

terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.71" }
  }
  backend "s3" {
    key          = "service.tfstate"
    region       = "us-east-2"
    use_lockfile = true
    encrypt      = true
  }
}

provider "aws" {
  region = var.region
  default_tags { tags = { Project = "phish-triage" } }
}

data "aws_caller_identity" "me" {}

data "aws_ecr_repository" "service" {
  name = "phish-triage"
}

locals {
  role_boundary = var.ci_role_boundary ? "arn:aws:iam::${data.aws_caller_identity.me.account_id}:policy/phish-triage-svc-boundary" : null
  name          = "phish-triage"
  # one owner per line, the same file `make retrain` reads (data/retraining.py)
  retraining_owners = join(",", compact([for line in split("\n", file("${path.module}/../retraining-owners")) : trimspace(line)]))
  image_uri         = "${data.aws_ecr_repository.service.repository_url}:${var.image_tag}"
  # backup: point-in-time recovery for what can't be rebuilt (the API keys, and feedback for retraining).
  # Verdicts expire after 90 days (`store_dynamo.VERDICT_DAYS`): a scan id is kept only as long as it's useful.
  tables = {
    keys     = { hash = "key_hash", range = null, range_type = null, ttl = false, backup = true }
    verdicts = { hash = "owner", range = "scan_id", range_type = "S", ttl = true, backup = false }
    feedback = { hash = "owner", range = "scan_at", range_type = "S", ttl = false, backup = true }
    rate     = { hash = "owner", range = "minute", range_type = "N", ttl = true, backup = false }
  }
}

# --- Tables: keys (hashed), verdicts, feedback, rate counters. No email is ever stored. ---

resource "aws_dynamodb_table" "t" {
  for_each     = local.tables
  name         = "${local.name}-${each.key}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = each.value.hash
  range_key    = each.value.range

  attribute {
    name = each.value.hash
    type = "S"
  }
  dynamic "attribute" {
    for_each = each.value.range == null ? [] : [each.value.range]
    content {
      name = attribute.value
      type = each.value.range_type
    }
  }
  dynamic "ttl" {
    for_each = each.value.ttl ? [1] : []
    content {
      attribute_name = "expires"
      enabled        = true
    }
  }
  server_side_encryption { enabled = true }
  # A rename or a key change would otherwise replace the table, keys and feedback with it, without asking.
  deletion_protection_enabled = true
  point_in_time_recovery { enabled = each.value.backup }
}

# --- The scan function ---

data "aws_iam_policy_document" "lambda_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "scan" {
  permissions_boundary = local.role_boundary
  name                 = "${local.name}-svc-scan"
  assume_role_policy   = data.aws_iam_policy_document.lambda_trust.json
}

data "aws_iam_policy_document" "scan" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.scan.arn}:*"]
  }
  # Each table only what the service does with it: it reads keys (never writes them: `make api-key` does that
  # from my laptop), reads and writes verdicts, adds feedback and counts requests.
  statement {
    actions   = ["dynamodb:GetItem"]
    resources = [aws_dynamodb_table.t["keys"].arn]
  }
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem"]
    resources = [aws_dynamodb_table.t["verdicts"].arn]
  }
  statement {
    actions   = ["dynamodb:PutItem"]
    resources = [aws_dynamodb_table.t["feedback"].arn]
  }
  statement {
    actions   = ["dynamodb:UpdateItem"]
    resources = [aws_dynamodb_table.t["rate"].arn]
  }
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.anthropic.arn]
  }
  statement {
    actions   = ["s3:PutObject"] # write only: the service can't read an email back
    resources = ["${aws_s3_bucket.retraining.arn}/emails/*"]
  }
}

resource "aws_iam_role_policy" "scan" {
  role   = aws_iam_role.scan.id
  policy = data.aws_iam_policy_document.scan.json
}

resource "aws_cloudwatch_log_group" "scan" {
  name              = "/aws/lambda/${local.name}-scan"
  retention_in_days = 14
}

resource "aws_lambda_function" "scan" {
  function_name = "${local.name}-scan"
  role          = aws_iam_role.scan.arn
  package_type  = "Image"
  image_uri     = local.image_uri
  architectures = ["arm64"]
  memory_size   = var.scan_memory_mb
  # API Gateway answers at 29 s, but the first load on a fresh image took 60 s (Lambda fetches the image lazily on
  # first read; later cold starts took about 20 s). Letting the function run on means the load finishes and the
  # next request is fast, instead of starting over each time. `make deploy-apply` warms it right after a deploy.
  timeout                        = 120
  reserved_concurrent_executions = var.scan_concurrency
  publish                        = true # each image is a numbered version; CodeDeploy moves the `live` alias to it
  environment {
    variables = {
      PHISH_TABLE_PREFIX      = local.name
      PHISH_BUNDLE_DIR        = "/opt/bundle"
      PHISH_EXPLANATIONS      = var.explanations_enabled ? "on" : "off"
      PHISH_ANTHROPIC_SECRET  = aws_secretsmanager_secret.anthropic.name
      PHISH_DAILY_LLM_USD     = tostring(var.daily_llm_usd)
      PHISH_RETRAINING_BUCKET = aws_s3_bucket.retraining.bucket
      PHISH_RETRAINING_OWNERS = local.retraining_owners # the only keys that may send emails for retraining
      LOKY_MAX_CPU_COUNT      = "1"                     # joblib can't count cores on Lambda and logs a traceback otherwise
    }
  }
  logging_config {
    log_format = "Text"
    log_group  = aws_cloudwatch_log_group.scan.name
  }
}

# Traffic reaches the function through the `live` alias. Terraform creates it; after that CodeDeploy moves it to each
# new version (scripts/canary.py, from `make deploy-apply`), so Terraform leaves where it points alone.
resource "aws_lambda_alias" "live" {
  name             = "live"
  function_name    = aws_lambda_function.scan.function_name
  function_version = aws_lambda_function.scan.version
  lifecycle {
    ignore_changes = [function_version, routing_config]
  }
}

# A ping every 5 minutes keeps one copy of the function loaded, so a scan seldom waits for a cold start.
resource "aws_cloudwatch_event_rule" "warm" {
  name                = "${local.name}-warm"
  description         = "Keep one scan function loaded"
  schedule_expression = "rate(5 minutes)"
}

resource "aws_cloudwatch_event_target" "warm" {
  rule = aws_cloudwatch_event_rule.warm.name
  arn  = aws_lambda_alias.live.arn
}

# The ping is the only asynchronous call: a failed one isn't retried (twice, by default), which would load the model
# three times per ping while something is broken, at 3 GB each.
resource "aws_lambda_function_event_invoke_config" "scan" {
  function_name          = aws_lambda_function.scan.function_name
  qualifier              = aws_lambda_alias.live.name
  maximum_retry_attempts = 0
}

resource "aws_lambda_permission" "warm" {
  statement_id  = "AllowWarmUpPing"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scan.function_name
  qualifier     = aws_lambda_alias.live.name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.warm.arn
}

# --- The API: HTTP API with throttling in front of the function ---

resource "aws_apigatewayv2_api" "http" {
  name          = local.name
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_integration" "scan" {
  api_id                 = aws_apigatewayv2_api.http.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_alias.live.invoke_arn
  payload_format_version = "2.0"
  timeout_milliseconds   = 29000
}

resource "aws_apigatewayv2_route" "all" {
  api_id    = aws_apigatewayv2_api.http.id
  route_key = "ANY /{proxy+}"
  target    = "integrations/${aws_apigatewayv2_integration.scan.id}"
}

resource "aws_cloudwatch_log_group" "api" {
  name              = "/aws/apigateway/${local.name}"
  retention_in_days = 14
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.http.id
  name        = "$default"
  auto_deploy = true
  default_route_settings {
    throttling_burst_limit = var.api_burst
    throttling_rate_limit  = var.api_rate_per_second
  }
  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api.arn
    # No client IP and no body: the request id, route, status and timings only.
    format = jsonencode({
      requestId = "$context.requestId", route = "$context.routeKey", status = "$context.status",
      latencyMs = "$context.responseLatency", integrationMs = "$context.integrationLatency",
      error     = "$context.integrationErrorMessage",
    })
  }
}

resource "aws_lambda_permission" "api" {
  statement_id  = "AllowApiGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scan.function_name
  qualifier     = aws_lambda_alias.live.name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.http.execution_arn}/*/*"
}

# --- Emails I send for retraining: the only email the service ever keeps, and only when I ask ---

# Written by the scan function (POST /v1/retraining-email), which can't read them back; read and deleted from my
# laptop by `make retrain`. Not versioned, so a deleted email is gone, and each one expires after 90 days anyway.
resource "aws_s3_bucket" "retraining" {
  bucket = "${local.name}-retraining-${data.aws_caller_identity.me.account_id}"
}

resource "aws_s3_bucket_public_access_block" "retraining" {
  bucket                  = aws_s3_bucket.retraining.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "retraining" {
  bucket = aws_s3_bucket.retraining.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "retraining" {
  bucket = aws_s3_bucket.retraining.id
  rule {
    id     = "delete-after-90-days"
    status = "Enabled"
    filter {}
    expiration { days = 90 }
  }
}

data "aws_iam_policy_document" "retraining_tls" {
  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.retraining.arn, "${aws_s3_bucket.retraining.arn}/*"]
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

resource "aws_s3_bucket_policy" "retraining" {
  bucket = aws_s3_bucket.retraining.id
  policy = data.aws_iam_policy_document.retraining_tls.json
}

# --- Explanations, on demand: the scan function calls Anthropic in the request (service/explain.py) ---

# The key's value is put from my laptop (`make put-anthropic-key`, read from .env), never through Terraform, so it
# isn't in the plan or the state. Only the scan function can read it.
resource "aws_secretsmanager_secret" "anthropic" {
  name                    = "${local.name}/anthropic-api-key"
  description             = "Anthropic API key for on-demand explanations"
  recovery_window_in_days = 7
}

# --- Canary: CodeDeploy moves `live` 10% for 10 minutes, after a smoke check, and rolls back on the alarms ---

resource "aws_iam_role" "codedeploy" {
  permissions_boundary = local.role_boundary
  name                 = "${local.name}-svc-codedeploy"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Principal = { Service = "codedeploy.amazonaws.com" } }]
  })
}

# AWS's policy for Lambda deployments: update aliases, read alarms, and invoke hooks named CodeDeployHook_*.
resource "aws_iam_role_policy_attachment" "codedeploy" {
  role       = aws_iam_role.codedeploy.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRoleForLambda"
}

resource "aws_codedeploy_app" "scan" {
  name             = local.name
  compute_platform = "Lambda"
}

resource "aws_codedeploy_deployment_group" "scan" {
  app_name               = aws_codedeploy_app.scan.name
  deployment_group_name  = "${local.name}-scan"
  service_role_arn       = aws_iam_role.codedeploy.arn
  deployment_config_name = "CodeDeployDefault.LambdaCanary10Percent10Minutes"
  deployment_style {
    deployment_option = "WITH_TRAFFIC_CONTROL"
    deployment_type   = "BLUE_GREEN"
  }
  alarm_configuration {
    enabled = true
    alarms = [
      aws_cloudwatch_metric_alarm.a["scan-errors"].alarm_name,
      aws_cloudwatch_metric_alarm.a["api-5xx"].alarm_name,
      aws_cloudwatch_metric_alarm.scan_p95.alarm_name,
    ]
  }
  auto_rollback_configuration {
    enabled = true
    events  = ["DEPLOYMENT_FAILURE", "DEPLOYMENT_STOP_ON_ALARM"]
  }
}

# The BeforeAllowTraffic hook (`lambda_handler.before_traffic`): the same image, a small function that runs the smoke
# check on the new version and passes or fails the deployment. Its name must start with CodeDeployHook_ for AWS's
# policy above to invoke it.
resource "aws_iam_role" "smoke" {
  permissions_boundary = local.role_boundary
  name                 = "${local.name}-svc-smoke"
  assume_role_policy   = data.aws_iam_policy_document.lambda_trust.json
}

data "aws_iam_policy_document" "smoke" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.smoke.arn}:*"]
  }
  statement {
    actions   = ["codedeploy:GetDeployment", "codedeploy:PutLifecycleEventHookExecutionStatus"]
    resources = ["*"] # the deployment id is only known when the hook runs
  }
  statement {
    actions   = ["lambda:InvokeFunction"]
    resources = ["${aws_lambda_function.scan.arn}:*"] # a numbered version of the scan function
  }
}

resource "aws_iam_role_policy" "smoke" {
  role   = aws_iam_role.smoke.id
  policy = data.aws_iam_policy_document.smoke.json
}

resource "aws_cloudwatch_log_group" "smoke" {
  name              = "/aws/lambda/CodeDeployHook_${local.name}-smoke"
  retention_in_days = 14
}

resource "aws_lambda_function" "smoke" {
  function_name = "CodeDeployHook_${local.name}-smoke"
  role          = aws_iam_role.smoke.arn
  package_type  = "Image"
  image_uri     = local.image_uri
  architectures = ["arm64"]
  memory_size   = 512
  timeout       = 300 # the new version's first model load takes up to a minute
  image_config {
    command = ["phish_triage.service.lambda_handler.before_traffic"]
  }
  logging_config {
    log_format = "Text"
    log_group  = aws_cloudwatch_log_group.smoke.name
  }
}

# --- The weekly drift check (service/drift.py): PSI of this week's verdicts against held-out legitimate mail ---

resource "aws_iam_role" "drift" {
  permissions_boundary = local.role_boundary
  name                 = "${local.name}-svc-drift"
  assume_role_policy   = data.aws_iam_policy_document.lambda_trust.json
}

data "aws_iam_policy_document" "drift" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.drift.arn}:*"]
  }
  statement {
    actions   = ["dynamodb:Scan"] # the stored verdicts only (score, stage, sender check); never an email
    resources = [aws_dynamodb_table.t["verdicts"].arn]
  }
  statement {
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"] # PutMetricData has no resource; the condition keeps it to the drift namespace
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["phish-triage/drift"]
    }
  }
}

resource "aws_iam_role_policy" "drift" {
  role   = aws_iam_role.drift.id
  policy = data.aws_iam_policy_document.drift.json
}

resource "aws_cloudwatch_log_group" "drift" {
  name              = "/aws/lambda/${local.name}-drift"
  retention_in_days = 14
}

resource "aws_lambda_function" "drift" {
  function_name = "${local.name}-drift"
  role          = aws_iam_role.drift.arn
  package_type  = "Image"
  image_uri     = local.image_uri
  architectures = ["arm64"]
  memory_size   = 512
  timeout       = 120
  image_config {
    command = ["phish_triage.service.drift.handler"]
  }
  environment {
    variables = { PHISH_TABLE_PREFIX = local.name }
  }
  logging_config {
    log_format = "Text"
    log_group  = aws_cloudwatch_log_group.drift.name
  }
}

resource "aws_cloudwatch_event_rule" "drift" {
  name                = "${local.name}-drift"
  description         = "Compare this week's verdicts with the drift reference"
  schedule_expression = "cron(0 13 ? * MON *)" # Mondays, 13:00 UTC
}

resource "aws_cloudwatch_event_target" "drift" {
  rule = aws_cloudwatch_event_rule.drift.name
  arn  = aws_lambda_function.drift.arn
}

resource "aws_lambda_permission" "drift" {
  statement_id  = "AllowWeeklyDrift"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.drift.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.drift.arn
}

resource "aws_cloudwatch_metric_alarm" "drift" {
  alarm_name          = "${local.name}-drift"
  alarm_description   = "This week's verdicts moved away from the reference: a PSI above 0.25 (service/drift.py)"
  namespace           = "phish-triage/drift"
  metric_name         = "MaxPSI"
  statistic           = "Maximum"
  period              = 86400
  evaluation_periods  = 1
  threshold           = 0.25
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching" # a week with too few scans publishes no number
  alarm_actions       = [aws_sns_topic.alarms.arn]
}

# --- Alarms and a dashboard ---

resource "aws_sns_topic" "alarms" {
  name = "${local.name}-alarms"
}

resource "aws_sns_topic_subscription" "email" {
  count     = nonsensitive(var.alert_email == "") ? 0 : 1
  topic_arn = aws_sns_topic.alarms.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

locals {
  alarms = {
    "scan-errors" = {
      namespace  = "AWS/Lambda", metric = "Errors", stat = "Sum", threshold = 1, periods = 1,
      dimensions = { FunctionName = aws_lambda_function.scan.function_name },
      text       = "The scan function failed at least once in 5 minutes"
    }
    "scan-throttles" = {
      namespace  = "AWS/Lambda", metric = "Throttles", stat = "Sum", threshold = 1, periods = 1,
      dimensions = { FunctionName = aws_lambda_function.scan.function_name },
      text       = "Scans were refused because the concurrency limit was reached"
    }
    "api-5xx" = {
      namespace  = "AWS/ApiGateway", metric = "5xx", stat = "Sum", threshold = 1, periods = 1,
      dimensions = { ApiId = aws_apigatewayv2_api.http.id, Stage = "$default" },
      text       = "The API returned a server error"
    }
    "api-requests" = {
      namespace  = "AWS/ApiGateway", metric = "Count", stat = "Sum", threshold = 1500, periods = 1,
      dimensions = { ApiId = aws_apigatewayv2_api.http.id, Stage = "$default" },
      text       = "About 5 requests a second for 5 minutes, the throttle's rate: far above my use, and each costs money"
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "a" {
  for_each            = local.alarms
  alarm_name          = "${local.name}-${each.key}"
  alarm_description   = each.value.text
  namespace           = each.value.namespace
  metric_name         = each.value.metric
  statistic           = each.value.stat
  dimensions          = each.value.dimensions
  period              = 300
  evaluation_periods  = each.value.periods
  threshold           = each.value.threshold
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]
}

# On the API's latency, what a caller waits for: the function's own duration also counts the 5-minute warm-up pings
# and model loads (60 s on a new image), so it fired on every deploy with nobody waiting.
resource "aws_cloudwatch_metric_alarm" "scan_p95" {
  alarm_name          = "${local.name}-scan-p95"
  alarm_description   = "Requests are slow: API p95 above ${var.p95_alarm_ms} ms for 15 minutes"
  namespace           = "AWS/ApiGateway"
  metric_name         = "Latency"
  extended_statistic  = "p95"
  dimensions          = { ApiId = aws_apigatewayv2_api.http.id, Stage = "$default" }
  period              = 300
  evaluation_periods  = 3
  threshold           = var.p95_alarm_ms
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]
}

resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = local.name
  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric", x = 0, y = 0, width = 12, height = 6,
        properties = {
          title = "Scans and errors", region = var.region, stat = "Sum", period = 300,
          metrics = [
            ["AWS/Lambda", "Invocations", "FunctionName", aws_lambda_function.scan.function_name],
            [".", "Errors", ".", "."], [".", "Throttles", ".", "."],
          ]
        }
      },
      {
        type = "metric", x = 12, y = 0, width = 12, height = 6,
        properties = {
          title = "Scan time (ms)", region = var.region, period = 300,
          metrics = [
            ["AWS/Lambda", "Duration", "FunctionName", aws_lambda_function.scan.function_name, { stat = "p50" }],
            ["...", { stat = "p95" }],
          ]
        }
      },
      {
        type = "metric", x = 0, y = 6, width = 12, height = 6,
        properties = {
          title = "API status", region = var.region, stat = "Sum", period = 300,
          metrics = [
            ["AWS/ApiGateway", "Count", "ApiId", aws_apigatewayv2_api.http.id, "Stage", "$default"],
            [".", "4xx", ".", ".", ".", "."], [".", "5xx", ".", ".", ".", "."],
          ]
        }
      },
      {
        type = "metric", x = 12, y = 6, width = 12, height = 6,
        properties = {
          title   = "API latency (p95, ms)", region = var.region, stat = "p95", period = 300,
          metrics = [["AWS/ApiGateway", "Latency", "ApiId", aws_apigatewayv2_api.http.id, "Stage", "$default"]]
        }
      },
    ]
  })
}

output "api_url" { value = aws_apigatewayv2_api.http.api_endpoint }
output "scan_function" { value = aws_lambda_function.scan.function_name }
output "scan_version" { value = aws_lambda_function.scan.version }
output "retraining_bucket" { value = aws_s3_bucket.retraining.bucket }
