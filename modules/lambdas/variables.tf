variable "enable_lambdas" {
  type = bool
}

variable "slack_topic_arn" {
  type = string
}

variable "region" {
  type = string
}

variable "s3_bucket_enforce_encryption_exceptions" {
  type = list(string)
}

variable "s3_bucket_block_publicaccess_exceptions" {
  type = list(string)
}
