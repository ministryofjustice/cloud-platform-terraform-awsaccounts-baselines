# START: Global vars
variable "region" {
  type        = string
  description = "Region the SNS topic is in"
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
# END: Global vars

# START: logging module
variable "enable_logging" {
  type        = bool
  default     = true
  description = "Enable/Disable logging module - it creates S3 buckets and forwards all cloudtrail logs to them"
}

variable "buckets_prefix" {
  type        = string
  default     = "cp"
  description = "Prefix for bucket names"
}

variable "buckets_suffix" {
  type        = string
  default     = "do-not-delete"
  description = "Suffix for bucket names"
}

variable "cloudtrail_name" {
  type        = string
  description = "The name of the trail which is going to be streaming logs to S3"
  default     = "cloud-platform-cloudtrail"
}
# END: logging module

# START: slack_integration module
variable "enable_slack_integration" {
  type        = bool
  default     = true
  description = "Enable/Disable slack integration module - it creates SNS and Lambda function to send slack notifications"
}

variable "slack_webhook" {
  description = "Slack Webhook URL for sending alerts"
  type        = string
  default     = ""
}

variable "slack_channel" {
  description = "Slack channel where alerts are sent"
  type        = string
  default     = ""
}
# END: slack_integration module

# START: cloudwatch module
variable "enable_cloudwatch" {
  type        = bool
  default     = true
  description = "Enable/Disable cloudwatch module."
}
# END: cloudwatch module

# START: lambdas module
variable "s3_bucket_enforce_encryption_exceptions" {
  type        = list(string)
  default     = [""]
  description = "S3 buckets exceptions for encryption remediation"
}

variable "s3_bucket_block_publicaccess_exceptions" {
  type        = list(string)
  default     = [""]
  description = "S3 buckets exceptions for publicaccess remediation"
}
# END: lambdas module
