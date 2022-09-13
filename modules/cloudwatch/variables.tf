variable "slack_topic_arn" {
  type        = string
  description = "SNS topic ARN to send notifications to Slack"
}

variable "enable_cloudwatch" {
  type        = bool
  description = "Whether to enable CloudWatch"
}
