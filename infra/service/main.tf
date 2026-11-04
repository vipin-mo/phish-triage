# Everything that runs: the scan function behind API Gateway, its DynamoDB tables, the (switched-off)
# explanation queue and worker, logs, alarms and a dashboard. Deployed from my laptop with `make deploy-plan` and
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
  name      = "phish-triage"
  image_uri = "${data.aws_ecr_repository.service.repository_url}:${var.image_tag}"
  tables = {
    keys     = { hash = "key_hash", range = null, range_type = null, ttl = false }
    verdicts = { hash = "owner", range = "scan_id", range_type = "S", ttl = false }
    feedback = { hash = "owner", range = "scan_at", range_type = "S", ttl = false }
    rate     = { hash = "owner", range = "minute", range_type = "N", ttl = true }
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
  name               = "${local.name}-svc-scan"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

data "aws_iam_policy_document" "scan" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.scan.arn}:*"]
  }
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"]
    resources = [for t in aws_dynamodb_table.t : t.arn]
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
  environment {
    variables = {
      PHISH_TABLE_PREFIX = local.name
      PHISH_BUNDLE_DIR   = "/opt/bundle"
      PHISH_EXPLANATIONS = "off"
      LOKY_MAX_CPU_COUNT = "1" # joblib can't count cores on Lambda and logs a traceback otherwise
    }
  }
  logging_config {
    log_format = "Text"
    log_group  = aws_cloudwatch_log_group.scan.name
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
  arn  = aws_lambda_function.scan.arn
}

resource "aws_lambda_permission" "warm" {
  statement_id  = "AllowWarmUpPing"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scan.function_name
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
  integration_uri        = aws_lambda_function.scan.invoke_arn
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
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.http.execution_arn}/*/*"
}

# --- Explanations: built, switched off (no trigger, no Anthropic key in AWS) ---

resource "aws_sqs_queue" "explain_dlq" {
  name                      = "${local.name}-explain-dlq"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
}

resource "aws_sqs_queue" "explain" {
  name                       = "${local.name}-explain"
  visibility_timeout_seconds = 120
  message_retention_seconds  = 86400
  sqs_managed_sse_enabled    = true
  redrive_policy             = jsonencode({ deadLetterTargetArn = aws_sqs_queue.explain_dlq.arn, maxReceiveCount = 3 })
}

resource "aws_iam_role" "explain" {
  name               = "${local.name}-svc-explain"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

data "aws_iam_policy_document" "explain" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.explain.arn}:*"]
  }
  statement {
    actions   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
    resources = [aws_sqs_queue.explain.arn]
  }
}

resource "aws_iam_role_policy" "explain" {
  role   = aws_iam_role.explain.id
  policy = data.aws_iam_policy_document.explain.json
}

resource "aws_cloudwatch_log_group" "explain" {
  name              = "/aws/lambda/${local.name}-explain"
  retention_in_days = 14
}

resource "aws_lambda_function" "explain" {
  function_name = "${local.name}-explain"
  role          = aws_iam_role.explain.arn
  package_type  = "Image"
  image_uri     = local.image_uri
  architectures = ["arm64"]
  memory_size   = 512
  timeout       = 60

  reserved_concurrent_executions = 1 # threat model rule 11: every function has a cap
  image_config {
    command = ["phish_triage.service.lambda_handler.explain"]
  }
  environment {
    variables = { PHISH_EXPLANATIONS = "off" }
  }
  logging_config {
    log_format = "Text"
    log_group  = aws_cloudwatch_log_group.explain.name
  }
}

resource "aws_lambda_event_source_mapping" "explain" {
  event_source_arn = aws_sqs_queue.explain.arn
  function_name    = aws_lambda_function.explain.arn
  batch_size       = 1
  enabled          = var.explanations_enabled
}

# --- Alarms and a dashboard ---

resource "aws_sns_topic" "alarms" {
  name = "${local.name}-alarms"
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email == "" ? 0 : 1
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
    "explain-dlq" = {
      namespace  = "AWS/SQS", metric = "ApproximateNumberOfMessagesVisible", stat = "Maximum", threshold = 1, periods = 1,
      dimensions = { QueueName = aws_sqs_queue.explain_dlq.name },
      text       = "A message reached the explanation dead-letter queue"
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

resource "aws_cloudwatch_metric_alarm" "scan_p95" {
  alarm_name          = "${local.name}-scan-p95"
  alarm_description   = "Scans are slow: p95 above ${var.p95_alarm_ms} ms for 15 minutes"
  namespace           = "AWS/Lambda"
  metric_name         = "Duration"
  extended_statistic  = "p95"
  dimensions          = { FunctionName = aws_lambda_function.scan.function_name }
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
          title   = "Explanation dead-letter queue", region = var.region, stat = "Maximum", period = 300,
          metrics = [["AWS/SQS", "ApproximateNumberOfMessagesVisible", "QueueName", aws_sqs_queue.explain_dlq.name]]
        }
      },
    ]
  })
}

output "api_url" { value = aws_apigatewayv2_api.http.api_endpoint }
output "scan_function" { value = aws_lambda_function.scan.function_name }
