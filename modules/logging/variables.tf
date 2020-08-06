
variable "buckets_prefix" {
  type = string
}

variable "buckets_suffix" {
  type = string
}

variable "tags" {
  type = map(string)
}

variable "region" {
  type = string
}

variable "cloudtrail_name" {
  type        = string
}

variable "enable_logging" {
  type        = bool
}