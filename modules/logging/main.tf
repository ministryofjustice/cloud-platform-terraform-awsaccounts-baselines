data "aws_caller_identity" "current" {}

locals {
  configlogs_bucket_name     = "${var.buckets_prefix}-configlogs-${data.aws_caller_identity.current.account_id}-${var.buckets_suffix}"
  accesslogs_bucket_name     = "${var.buckets_prefix}-accesslog-${data.aws_caller_identity.current.account_id}-${var.buckets_suffix}"
  cloudtraillogs_bucket_name = "${var.buckets_prefix}-cloudtraillogs-${data.aws_caller_identity.current.account_id}-${var.buckets_suffix}"
}

#####################
# Cloudtrail Bucket #
#####################

data "aws_iam_policy_document" "cloudtraillogs" {
  count = var.enable_logging ? 1 : 0

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
  count = var.enable_logging ? 1 : 0

  bucket = local.cloudtraillogs_bucket_name
  policy = data.aws_iam_policy_document.cloudtraillogs.0.json

  versioning {
    enabled = true
  }

  logging {
    target_bucket = aws_s3_bucket.accesslogs.0.id
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
    id      = "cloudtraillogs"
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

resource "aws_s3_bucket_public_access_block" "cloudtraillogs" {
  count = var.enable_logging ? 1 : 0

  bucket                  = aws_s3_bucket.cloudtraillogs.0.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

###############
# Config Logs #
###############

data "aws_iam_policy_document" "configlogs" {
  count = var.enable_logging ? 1 : 0

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
  count = var.enable_logging ? 1 : 0

  bucket = local.configlogs_bucket_name
  policy = data.aws_iam_policy_document.configlogs.0.json

  versioning {
    enabled = true
  }

  logging {
    target_bucket = aws_s3_bucket.accesslogs.0.id
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
    id      = "configlogs"
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

resource "aws_s3_bucket_public_access_block" "configlogs" {
  count = var.enable_logging ? 1 : 0

  bucket                  = aws_s3_bucket.configlogs.0.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

###############
# Access Logs #
###############

resource "aws_s3_bucket" "accesslogs" {
  count = var.enable_logging ? 1 : 0

  bucket = local.accesslogs_bucket_name
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

resource "aws_s3_bucket_public_access_block" "accesslogs" {
  count = var.enable_logging ? 1 : 0

  bucket                  = aws_s3_bucket.accesslogs.0.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

##############
# CloudTrail #
##############

resource "aws_cloudtrail" "cloud-platform_cloudtrail" {
  count = var.enable_logging ? 1 : 0

  name                          = var.cloudtrail_name
  s3_bucket_name                = aws_s3_bucket.cloudtraillogs.0.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  tags = var.tags
}
