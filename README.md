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

| Name         | Description | Type | Default | Required |
|--------------|-------------|:----:|:-----:|:-----:|
| account_name | Name of the account, used in almost all resources to identify and tag | string | | yes |
| region | Region where resources are going to be created/deployed | string | | yes |
| buckets_prefix | The prefix used for the S3 buckets which are going to be created | string | `cp-aws` | no |
| buckets_suffix | The suffix used for the S3 buckets which are going to be created | string | `-do-not-delete` | no |

## Outputs

| Name | Description |
|------|-------------|
| logging_buckets | Buckets created for logging |
