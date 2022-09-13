variable "slack_topic_arn" {
  type        = string
  description = "SNS topic ARN to send notifications to Slack"
}

variable "region" {
  type        = string
  description = "Region the SNS topic is in"
}

variable "s3_bucket_enforce_encryption_exceptions" {
  type        = list(string)
  description = "S3 bucket ARNs for exceptions to enforced encryption"
}

variable "s3_bucket_block_publicaccess_exceptions" {
  type        = list(string)
  description = "S3 bucket ARNs for exceptions to public access"
}
