
output "buckets" {
  description = "Buckets created for all account logs related"
  value       = [ aws_s3_bucket.cloudtraillogs.*.id , aws_s3_bucket.configlogs.*.id , aws_s3_bucket.accesslogs.*.id ]
}