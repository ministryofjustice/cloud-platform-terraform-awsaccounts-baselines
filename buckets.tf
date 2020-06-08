locals {
  configlogs_bucket_name     = "${var.buckets_prefix}-configlogs-${data.aws_caller_identity.current.account_id}-${var.buckets_suffix}"
  accesslogs_bucket_name     = "${var.buckets_prefix}-accesslog-${data.aws_caller_identity.current.account_id}-${var.buckets_suffix}"
  cloudtraillogs_bucket_name = "${var.buckets_prefix}-cloudtraillogs-${data.aws_caller_identity.current.account_id}-${var.buckets_suffix}"
}

#####################
# Cloudtrail Bucket #
#####################

data "aws_iam_policy_document" "cloudtraillogs" {
  statement {
    sid    = "CloudTrailBucketPolicy9999"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions = [
      "s3:GetBucketAcl",
    ]

    resources = [
      "arn:aws:s3:::${local.cloudtraillogs_bucket_name}",
    ]
  }

  statement {
    sid    = "CloudTrailBucketPolicy9998"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions = [
      "s3:PutObject",
    ]

    resources = [
      "arn:aws:s3:::${local.cloudtraillogs_bucket_name}/*",
    ]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"

      values = [
        "bucket-owner-full-control",
      ]
    }
  }
}

resource "aws_s3_bucket" "cloudtraillogs" {
  bucket = local.cloudtraillogs_bucket_name
  region = var.region
  policy = data.aws_iam_policy_document.cloudtraillogs.json

  versioning {
    enabled = true
  }

  logging {
    target_bucket = aws_s3_bucket.accesslogs.id
    target_prefix = "log/"
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  lifecycle_rule {
    id      = "accesslog_rules"
    enabled = true

    expiration {
      days = 730
    }

    noncurrent_version_expiration {
      days = 730
    }

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 60
      storage_class = "GLACIER"
    }

    noncurrent_version_transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    noncurrent_version_transition {
      days          = 60
      storage_class = "GLACIER"
    }
  }

  tags = var.tags
}

###############
# Config Logs #
###############

data "aws_iam_policy_document" "configlogs" {
  statement {
    sid    = "AWSConfigBucketPermissionsCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    actions = [
      "s3:GetBucketAcl",
    ]

    resources = [
      "arn:aws:s3:::${local.configlogs_bucket_name}",
    ]
  }

  statement {
    sid    = "AWSConfigBucketDelivery"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    actions = [
      "s3:PutObject",
    ]

    resources = [
      "arn:aws:s3:::${local.configlogs_bucket_name}/*",
    ]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"

      values = [
        "bucket-owner-full-control",
      ]
    }
  }
}

resource "aws_s3_bucket" "configlogs" {
  bucket = local.configlogs_bucket_name
  region = var.region
  policy = data.aws_iam_policy_document.configlogs.json

  versioning {
    enabled = true
  }

  logging {
    target_bucket = aws_s3_bucket.accesslogs.id
    target_prefix = "log/"
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  lifecycle_rule {
    id      = "accesslog_rules"
    enabled = true

    expiration {
      days = 425
    }

    noncurrent_version_expiration {
      days = 425
    }

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 60
      storage_class = "GLACIER"
    }

    noncurrent_version_transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    noncurrent_version_transition {
      days          = 60
      storage_class = "GLACIER"
    }
  }

  tags = var.tags
}

###############
# Access Logs #
###############

resource "aws_s3_bucket" "accesslogs" {
  bucket = local.accesslogs_bucket_name
  region = var.region
  acl    = "log-delivery-write"

  versioning {
    enabled = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  lifecycle_rule {
    id      = "accesslog_rules"
    enabled = true

    expiration {
      days = 425
    }

    noncurrent_version_expiration {
      days = 425
    }

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 60
      storage_class = "GLACIER"
    }

    noncurrent_version_transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    noncurrent_version_transition {
      days          = 60
      storage_class = "GLACIER"
    }
  }

  tags = var.tags
}
