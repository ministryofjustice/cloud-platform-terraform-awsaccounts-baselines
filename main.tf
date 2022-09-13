module "logging" {
  source = "./modules/logging"

  enable_logging  = var.enable_logging
  buckets_prefix  = var.buckets_prefix
  buckets_suffix  = var.buckets_suffix
  cloudtrail_name = var.cloudtrail_name

  tags = var.tags
}

module "slack_integration" {
  source  = "terraform-aws-modules/notify-slack/aws"
  version = "~> v5.0"

  create = var.enable_slack_integration

  sns_topic_name    = "slack-topic"
  slack_webhook_url = var.slack_webhook
  slack_channel     = var.slack_channel
  slack_username    = "reporter"

  tags = var.tags
}

module "cloudwatch" {
  source = "./modules/cloudwatch"

  enable_cloudwatch = var.enable_cloudwatch
  slack_topic_arn   = module.slack_integration.this_slack_topic_arn
}

module "lambdas" {
  source = "./modules/lambdas"

  region                                  = var.region
  slack_topic_arn                         = module.slack_integration.this_slack_topic_arn
  s3_bucket_enforce_encryption_exceptions = var.s3_bucket_enforce_encryption_exceptions
  s3_bucket_block_publicaccess_exceptions = var.s3_bucket_block_publicaccess_exceptions
}
