# cloud-platform-terraform-awsaccounts-baselines

This module includes security and operational baselines implemented by Cloud Platform team in their AWS Accounts.

## Usage

```hcl
module "baselines" {
  source = "github.com/ministryofjustice/cloud-platform-terraform-awsaccounts-baselines?ref=0.0.1"

  account_name = "cloud-platform-production"
}
```
## Inputs

| Name           | Description | Type | Default | Required |
|----------------|-------------|:----:|:-------:|:--------:|
| region         | Region where resources are going to be created/deployed | string | | yes |
| enable_logging | Enable/Disable logging module - it creates S3 buckets and forwards all cloudtrail logs to them | bool | true | no |
| enable_slack_integration | Enable/Disable slack integration module - it creates SNS and Lambda function to send slack notifications  | bool | true | no |
| enable_cloudwatch | Enable/Disable cloudwatch module | bool | true | no |
| tags | Tags for every single resource | map(string) | (check variables file) | no |
| buckets_prefix | The prefix used for the S3 buckets which are going to be created | string | `cp-` | no |
| buckets_suffix | The suffix used for the S3 buckets which are going to be created | string | `-do-not-delete` | no 
| slack_webhook | Slack Webhook URL for sending alerts | string | | no |
| slack_channel | Slack channel where alerts are sent | string | | no |

## Outputs

| Name | Description |
|------|-------------|
| logging_buckets | Buckets created for logging |
