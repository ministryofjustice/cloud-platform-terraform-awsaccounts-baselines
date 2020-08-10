###################
# Common policies #
###################

data "aws_iam_policy" "AWSLambdaBasicExecutionRole" {
  arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

############################################
# S3 Bucket - Check and Enforce Encryption #
############################################

# Determine encryption status of S3 buckets in the AWS account and set the default encryption

data "aws_iam_policy_document" "s3_bucket_encryption_permissions" {
  statement {
    sid    = "ListBucketPermissions"
    effect = "Allow"

    actions = [
      "s3:ListBucket",
      "s3:ListAllMyBuckets",
      "s3:GetEncryptionConfiguration",
      "s3:PutEncryptionConfiguration"
    ]

    resources = [
      "arn:aws:s3:::*",
    ]
  }

  statement {
    sid    = "SnsPublishPermissions"
    effect = "Allow"

    actions = [
      "sns:Publish",
    ]

    resources = [
      var.slack_topic_arn,
    ]
  }
}

resource "aws_iam_role_policy" "s3_bucket_encryption_permissions" {
  name   = "s3-bucket-encryption-encryption-and-sns"
  role   = aws_iam_role.s3_bucket_encryption.id
  policy = data.aws_iam_policy_document.s3_bucket_encryption_permissions.json
}

resource "aws_iam_role_policy" "s3_bucket_encryption_lambda_policy" {
  name   = "s3-bucket-encryption-basic-execution-role"
  role   = aws_iam_role.s3_bucket_encryption.id
  policy = data.aws_iam_policy.AWSLambdaBasicExecutionRole.policy
}

resource "aws_iam_role" "s3_bucket_encryption" {
  name               = "s3-bucket-encryption"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "archive_file" "s3_bucket_encryption_zip" {
  type        = "zip"
  source_file = "${path.module}/functions/s3-bucket-enable-default-encryption/index.py"
  output_path = "${path.module}/files/s3-bucket-enable-default-encryption.zip"
}

resource "aws_lambda_function" "s3_bucket_encryption" {
  filename      = "${path.module}/files/s3-bucket-enable-default-encryption.zip"
  function_name = "S3BucketEncryption"
  handler       = "index.lambda_handler"
  role          = aws_iam_role.s3_bucket_encryption.arn
  runtime       = "python3.6"
  timeout       = 600

  environment {
    variables = {
      TOPIC_ARN    = var.slack_topic_arn
      TOPIC_REGION = var.region
      S3_EXCEPTION = join(" ", var.s3_bucket_enforce_encryption_exceptions)
    }
  }

  depends_on = [data.archive_file.s3_bucket_encryption_zip]
}

##########################
# CloudWatch event rules #
##########################

resource "aws_cloudwatch_event_rule" "s3_bucket_encryption" {
  name                = "S3Bucket-EnforceEncryption"
  description         = "Determine the list of S3 buckets that are not encrypted and apply default encryption"
  schedule_expression = "cron(0 12 ? * WED *)"
}

resource "aws_cloudwatch_event_target" "s3_bucket_encryption" {
  rule      = aws_cloudwatch_event_rule.s3_bucket_encryption.name
  target_id = "lambda"
  arn       = aws_lambda_function.s3_bucket_encryption.arn
}