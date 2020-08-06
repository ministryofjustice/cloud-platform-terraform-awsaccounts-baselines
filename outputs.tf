
output "logging_buckets" {
  description = "Buckets created for all account logs related"
  value       = module.logging.buckets
}