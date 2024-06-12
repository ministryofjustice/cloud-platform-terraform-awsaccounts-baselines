
output "logging_buckets" {
  description = "Buckets created for all account logs related"
  value       = module.logging.buckets
}

output "slack_sns_topic" {
  description = "Slack integration sns topic name"
  value       = module.slack_integration.this_slack_topic_arn
}

output "cloudtraillogs_bucket_arn" {
  description = "Cloudtrail logs S3 bucket arn"
  value = module.logging.cloudtraillogs_bucket_arn
}
