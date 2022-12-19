# cloud-platform-terraform-awsaccounts-baselines

This module includes security and operational baselines implemented by Cloud Platform team in their AWS Accounts.

## Usage

```hcl
module "baselines" {
  source = "github.com/ministryofjustice/cloud-platform-terraform-awsaccounts-baselines?ref=0.0.1"

  account_name = "cloud-platform-production"
}
```
<!--- BEGIN_TF_DOCS --->
<!--- END_TF_DOCS --->
