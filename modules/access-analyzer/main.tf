data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

resource "aws_accessanalyzer_analyzer" "default" {
  analyzer_name = var.access_analyzer_name
  tags          = var.tags
}

# Filter out IAM roles that are used by OIDC providers in this account, that also aren't public
resource "aws_accessanalyzer_archive_rule" "oidc_providers" {
  analyzer_name = aws_accessanalyzer_analyzer.default.analyzer_name
  rule_name     = "oidc-providers"

  filter {
    criteria = "resourceType"
    eq       = ["AWS::IAM::Role"]
  }

  filter {
    criteria = "isPublic"
    eq       = ["false"]
  }

  filter {
    criteria = "principal.Federated"
    contains = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/oidc.circleci.com/org/",                                     # CircleCI
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/oidc.eks.${data.aws_region.current.name}.amazonaws.com/id/", # EKS
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/token.actions.githubusercontent.com"                         # GitHub
    ]
  }
}
