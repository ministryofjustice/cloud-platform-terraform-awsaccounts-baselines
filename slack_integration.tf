
data "aws_iam_policy_document" "slack_integration_lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    principals {
      type        = "Service"
      identifiers = ["sns.amazonaws.com"]
    }
  }
}

data "aws_iam_policy" "AWSLambdaBasicExecutionRole" {
  arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "lambda_policy" {
  name   = "sns-invoke-lambda-slack-integration"
  role   = aws_iam_role.slack_integration_role.id
  policy = data.aws_iam_policy.AWSLambdaBasicExecutionRole.policy
}

resource "aws_iam_role" "slack_integration_role" {
  name               = "lambda-slack-integration"
  assume_role_policy = data.aws_iam_policy_document.slack_integration_lambda_assume.json
}

data "archive_file" "slack_integration_zip" {
  type        = "zip"
  source_file = "${path.module}/functions/slack-integration/index.py"
  output_path = "${path.module}/files/slack-integration.zip"
}

resource "aws_lambda_function" "slack_integration" {
  filename      = "${path.module}/files/slack-integration.zip"
  function_name = "SlackIntegration"
  handler       = "index.lambda_handler"
  role          = aws_iam_role.slack_integration_role.arn
  runtime       = "python3.6"

  environment {
    variables = {
      HOOK_URL      = var.slack_webhook
      SLACK_CHANNEL = var.slack_channel
    }
  }

  depends_on = [data.archive_file.slack_integration_zip]
}

resource "aws_lambda_permission" "with_sns" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.slack_integration.arn
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.slack_integration.arn
}

#######
# SNS #
#######

resource "aws_sns_topic" "slack_integration" {
  name = "SNS-SlackIntegration-AlarmTopic"
}

resource "aws_sns_topic_subscription" "slack_integration_to_lambda" {
  topic_arn = aws_sns_topic.slack_integration.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.slack_integration.arn
}

