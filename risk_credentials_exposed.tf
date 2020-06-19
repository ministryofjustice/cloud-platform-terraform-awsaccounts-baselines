#################
# Step Function #
#################

data "aws_iam_policy_document" "risk_creds_exposed_step_function" {
  statement {
    sid       = "ExecuteStateMachine"
    effect    = "Allow"
    actions   = ["states:StartExecution"]
    resources = ["*"]
  }
  statement {
    sid       = "LambdaInvocations"
    effect    = "Allow"
    actions   = ["lambda:InvokeFunction"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "risk_creds_exposed_step_function_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "risk_creds_exposed_step_function" {
  name               = "risk-creds-exposed-step-function"
  assume_role_policy = data.aws_iam_policy_document.risk_creds_exposed_step_function_assume.json
}

resource "aws_iam_role_policy" "risk_creds_exposed_step_function" {
  name   = "risk-creds-exposed-step-function"
  role   = aws_iam_role.risk_creds_exposed_step_function.id
  policy = data.aws_iam_policy_document.risk_creds_exposed_step_function.json
}

resource "aws_sfn_state_machine" "risk_creds_exposed" {
  name     = "credentials-exposed"
  role_arn = aws_iam_role.risk_creds_exposed_step_function.arn

  definition = <<EOF
{
  "Comment": "Deletes exposed IAM access keypairs and notifies security",
  "StartAt": "DeleteAccessKeyPair",
  "States": {
    "DeleteAccessKeyPair": {
      "Type": "Task",
      "Resource": "${aws_lambda_function.risk_creds_exposed_delete_access_key_pair.arn}",
      "Catch": [
        {
          "ErrorEquals": [ "ClientError" ],
          "ResultPath": "$.error-info",
          "Next": "NotifySecurity"
        }
      ],
      "Next": "LookupCloudTrailEvents"
    },
    "LookupCloudTrailEvents": {
      "Type": "Task",
      "Resource": "${aws_lambda_function.risk_creds_exposed_lookup_cloudtrail_events.arn}",
      "Next": "NotifySecurity"
    },
    "NotifySecurity": {
      "Type": "Task",
      "Resource": "${aws_lambda_function.risk_creds_exposed_notify.arn}",
      "End": true
    }
  }
}
EOF

}

##########################
# Delete Access Key Pair #
##########################

data "aws_iam_policy_document" "risk_creds_exposed_delete_access_key_pair" {
  statement {
    sid    = "DeleteIAMAccessKeyPair"
    effect = "Allow"

    actions = [
      "iam:DeleteAccessKey",
      "iam:UpdateAccessKey",
      "iam:GetAccessKeyLastUsed"
    ]

    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "risk_creds_exposed_delete_access_key_pair" {
  name   = "s3-bucket-encryption-encryption"
  role   = aws_iam_role.risk_creds_exposed_delete_access_key_pair.id
  policy = data.aws_iam_policy_document.risk_creds_exposed_delete_access_key_pair.json
}

resource "aws_iam_role_policy" "risk_creds_exposed_delete_access_key_pair_lambda_policy" {
  name   = "risk-creds-exposed-delete-keypair-basic-execution"
  role   = aws_iam_role.risk_creds_exposed_delete_access_key_pair.id
  policy = data.aws_iam_policy.AWSLambdaBasicExecutionRole.policy
}

resource "aws_iam_role" "risk_creds_exposed_delete_access_key_pair" {
  name               = "risk-creds-exposed-delete-keypair"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "archive_file" "risk_creds_exposed_delete_access_key_pair" {
  type        = "zip"
  source_file = "${path.module}/functions/risk_credentials_exposed/delete_access_key_pair/index.py"
  output_path = "${path.module}/files/risk_credentials_exposed-delete-keypair.zip"
}

resource "aws_lambda_function" "risk_creds_exposed_delete_access_key_pair" {
  filename      = "${path.module}/files/risk_credentials_exposed-delete-keypair.zip"
  function_name = "RiskCredsExposed-DeleteKeyPair"
  handler       = "index.lambda_handler"
  role          = aws_iam_role.risk_creds_exposed_delete_access_key_pair.arn
  runtime       = "python3.6"

  depends_on = [data.archive_file.risk_creds_exposed_delete_access_key_pair]
}

############################
# Lookup Cloudtrail Events #
############################

data "aws_iam_policy_document" "risk_creds_exposed_lookup_cloudtrail_events" {
  statement {
    sid       = "LookupCloudTrailEvents"
    effect    = "Allow"
    actions   = ["cloudtrail:LookupEvents"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "risk_creds_exposed_lookup_cloudtrail_events" {
  name   = "risk-creds-exposed-lookup-cloudtrail-events"
  role   = aws_iam_role.risk_creds_exposed_lookup_cloudtrail_events.id
  policy = data.aws_iam_policy_document.risk_creds_exposed_lookup_cloudtrail_events.json
}

resource "aws_iam_role_policy" "risk_creds_exposed_lookup_cloudtrail_events_lambda_policy" {
  name   = "risk-creds-exposed-lookup-cloudtrail-events"
  role   = aws_iam_role.risk_creds_exposed_lookup_cloudtrail_events.id
  policy = data.aws_iam_policy.AWSLambdaBasicExecutionRole.policy
}

resource "aws_iam_role" "risk_creds_exposed_lookup_cloudtrail_events" {
  name               = "risk-creds-exposed-lookup-cloudtrail-events"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "archive_file" "risk_creds_exposed_lookup_cloudtrail_events" {
  type        = "zip"
  source_file = "${path.module}/functions/risk_credentials_exposed/lookup_cloudtrail_events/index.py"
  output_path = "${path.module}/files/risk_credentials_exposed_lookup_cloudtrail_events.zip"
}

resource "aws_lambda_function" "risk_creds_exposed_lookup_cloudtrail_events" {
  filename      = "${path.module}/files/risk_credentials_exposed_lookup_cloudtrail_events.zip"
  function_name = "RiskCredsExposed-LookupCloudtrailEvents"
  handler       = "index.lambda_handler"
  role          = aws_iam_role.risk_creds_exposed_lookup_cloudtrail_events.arn
  runtime       = "python3.6"

  depends_on = [data.archive_file.risk_creds_exposed_lookup_cloudtrail_events]
}

###################
# Nofity Security #
###################

data "aws_iam_policy_document" "risk_creds_exposed_notify" {
  statement {
    sid       = "SnsPublishPermissions"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.slack_integration.arn]
  }
}

resource "aws_iam_role_policy" "risk_creds_exposed_notify" {
  name   = "risk-creds-exposed-notify"
  role   = aws_iam_role.risk_creds_exposed_notify.id
  policy = data.aws_iam_policy_document.risk_creds_exposed_notify.json
}

resource "aws_iam_role_policy" "risk_creds_exposed_notify_lambda_policy" {
  name   = "risk-creds-exposed-notify"
  role   = aws_iam_role.risk_creds_exposed_notify.id
  policy = data.aws_iam_policy.AWSLambdaBasicExecutionRole.policy
}

resource "aws_iam_role" "risk_creds_exposed_notify" {
  name               = "risk-creds-exposed-notify"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "archive_file" "risk_creds_exposed_notify" {
  type        = "zip"
  source_file = "${path.module}/functions/risk_credentials_exposed/notify_security/index.py"
  output_path = "${path.module}/files/risk_credentials_exposed_notify.zip"
}

resource "aws_lambda_function" "risk_creds_exposed_notify" {
  filename      = "${path.module}/files/risk_credentials_exposed_notify.zip"
  function_name = "RiskCredsExposed-Notify"
  handler       = "index.lambda_handler"
  role          = aws_iam_role.risk_creds_exposed_notify.arn
  runtime       = "python3.6"

  depends_on = [data.archive_file.risk_creds_exposed_notify]
}
