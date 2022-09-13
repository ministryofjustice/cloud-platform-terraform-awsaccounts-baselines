variable "buckets_prefix" {
  type        = string
  description = "Prefix for bucket names"
}

variable "buckets_suffix" {
  type        = string
  description = "Suffix for bucket names"
}

variable "tags" {
  type        = map(string)
  description = "Map of tags"
}

variable "cloudtrail_name" {
  type        = string
  description = "Name of CloudTrail trail"
}

variable "enable_logging" {
  type        = bool
  description = "Whether to enable CloudTrail"
}
