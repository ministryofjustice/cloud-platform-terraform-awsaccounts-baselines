
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

variable "tags" {
  description = "A map of tags to add to all resources."
  type        = map(string)
  default     = {}
}
