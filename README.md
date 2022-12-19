# cloud-platform-terraform-awsaccounts-baselines

This module includes security and operational baselines implemented by Cloud Platform team in their AWS Accounts.

## Usage

```hcl
module "baselines" {
  source = "github.com/ministryofjustice/cloud-platform-terraform-awsaccounts-baselines?ref=0.0.1"

  account_name = "cloud-platform-production"
}
```
<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 0.14 |

## Providers

No providers.

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_access_analyzer"></a> [access\_analyzer](#module\_access\_analyzer) | ./modules/access-analyzer | n/a |
| <a name="module_cloudwatch"></a> [cloudwatch](#module\_cloudwatch) | ./modules/cloudwatch | n/a |
| <a name="module_lambdas"></a> [lambdas](#module\_lambdas) | ./modules/lambdas | n/a |
| <a name="module_logging"></a> [logging](#module\_logging) | ./modules/logging | n/a |
| <a name="module_slack_integration"></a> [slack\_integration](#module\_slack\_integration) | terraform-aws-modules/notify-slack/aws | ~> v5.0 |

## Resources

No resources.

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_buckets_prefix"></a> [buckets\_prefix](#input\_buckets\_prefix) | Prefix for bucket names | `string` | `"cp"` | no |
| <a name="input_buckets_suffix"></a> [buckets\_suffix](#input\_buckets\_suffix) | Suffix for bucket names | `string` | `"do-not-delete"` | no |
| <a name="input_cloudtrail_name"></a> [cloudtrail\_name](#input\_cloudtrail\_name) | The name of the trail which is going to be streaming logs to S3 | `string` | `"cloud-platform-cloudtrail"` | no |
| <a name="input_enable_cloudwatch"></a> [enable\_cloudwatch](#input\_enable\_cloudwatch) | Enable/Disable cloudwatch module. | `bool` | `true` | no |
| <a name="input_enable_logging"></a> [enable\_logging](#input\_enable\_logging) | Enable/Disable logging module - it creates S3 buckets and forwards all cloudtrail logs to them | `bool` | `true` | no |
| <a name="input_enable_slack_integration"></a> [enable\_slack\_integration](#input\_enable\_slack\_integration) | Enable/Disable slack integration module - it creates SNS and Lambda function to send slack notifications | `bool` | `true` | no |
| <a name="input_region"></a> [region](#input\_region) | Region the SNS topic is in | `string` | n/a | yes |
| <a name="input_s3_bucket_block_publicaccess_exceptions"></a> [s3\_bucket\_block\_publicaccess\_exceptions](#input\_s3\_bucket\_block\_publicaccess\_exceptions) | S3 buckets exceptions for publicaccess remediation | `list(string)` | <pre>[<br>  ""<br>]</pre> | no |
| <a name="input_s3_bucket_enforce_encryption_exceptions"></a> [s3\_bucket\_enforce\_encryption\_exceptions](#input\_s3\_bucket\_enforce\_encryption\_exceptions) | S3 buckets exceptions for encryption remediation | `list(string)` | <pre>[<br>  ""<br>]</pre> | no |
| <a name="input_slack_channel"></a> [slack\_channel](#input\_slack\_channel) | Slack channel where alerts are sent | `string` | `""` | no |
| <a name="input_slack_webhook"></a> [slack\_webhook](#input\_slack\_webhook) | Slack Webhook URL for sending alerts | `string` | `""` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | A map of tags to add to all resources. | `map(string)` | <pre>{<br>  "business-unit": "mojdigital",<br>  "infrastructure-support": "platform@digital.justice.gov.uk",<br>  "owner": "cloud-platform"<br>}</pre> | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_logging_buckets"></a> [logging\_buckets](#output\_logging\_buckets) | Buckets created for all account logs related |
| <a name="output_slack_sns_topic"></a> [slack\_sns\_topic](#output\_slack\_sns\_topic) | Slack integration sns topic name |
<!-- END_TF_DOCS -->
