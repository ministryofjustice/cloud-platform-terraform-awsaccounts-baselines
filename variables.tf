
# variable "enable_s3_bucket_object_auto_remediation" {
#   description = "Slack Webhook URL for sending alerts"
#   type        = bool
#   default = false
# }

variable "account_name" {
  type = string
}

variable "region" {
  type = string
}

variable "buckets_prefix" {
  type    = string
  default = "cp-aws"
}

variable "buckets_suffix" {
  type    = string
  default = "do-not-delete"
}

variable "slack_webhook" {
  description = "Slack Webhook URL for sending alerts"
  type        = string
}

variable "slack_channel" {
  description = "Slack channel where alerts are sent"
  type        = string
}

variable "tags" {
  description = "A map of tags to add to all resources."
  type        = map(string)
  default = {
    business-unit          = "mojdigital"
    owner                  = "cloud-platform"
    infrastructure-support = "platform@digital.justice.gov.uk"
  }
}

variable "cloudtrail_name" {
  type        = string
  description = "The name of the trail which is going to be streaming logs to S3"
  default     = "cloud-platform-cloudtrail"
}

variable "s3_bucket_enforce_encryption_exceptions" {
  type        = list
  description = "List of S3 buckets exceptions what S3 encryption Lambda enforcement is going to SKIP"
  default     = []
}

variable "s3_bucket_block_publickaccess_exceptions" {
  type        = list
  description = "List of S3 buckets that S3 lambda function will SKIP the enforcement"
  default     = []
}
