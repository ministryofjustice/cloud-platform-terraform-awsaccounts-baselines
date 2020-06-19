##########
# Groups #
##########

module "iam_group_with_policies_IAMFullAccess" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-group-with-policies"
  version = "~> 2.0"

  name                              = "IAMFullAccess"
  group_users                       = []
  attach_iam_self_management_policy = true
  custom_group_policy_arns = [
    "arn:aws:iam::aws:policy/IAMFullAccess",
    aws_iam_policy.user_malicious_activity_deny.arn
  ]
}

module "iam_group_with_policies_BillingAdmin" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-group-with-policies"
  version = "~> 2.0"

  name                              = "BillingAdmin"
  group_users                       = []
  attach_iam_self_management_policy = true
  custom_group_policy_arns = [
    "arn:aws:iam::aws:policy/AWSAccountUsageReportAccess",
    "arn:aws:iam::aws:policy/AWSAccountActivityAccess",
    aws_iam_policy.user_malicious_activity_deny.arn
  ]
}

module "iam_group_with_policies_InfraAdmin" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-group-with-policies"
  version = "~> 2.0"

  name                              = "InfraAdmin"
  group_users                       = []
  attach_iam_self_management_policy = true
  custom_group_policy_arns = [
    "arn:aws:iam::aws:policy/AdministratorAccess",
    aws_iam_policy.user_malicious_activity_deny.arn
  ]
}

module "iam_group_with_policies_NetworkAdmin" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-group-with-policies"
  version = "~> 2.0"

  name                              = "NetworkAdmin"
  group_users                       = []
  attach_iam_self_management_policy = true
  custom_group_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonVPCFullAccess",
    "arn:aws:iam::aws:policy/AWSDirectConnectFullAccess",
    "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess",
    "arn:aws:iam::aws:policy/AmazonRDSFullAccess",
    aws_iam_policy.user_malicious_activity_deny.arn
  ]
}

module "iam_group_with_policies_UserDeveloper" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-group-with-policies"
  version = "~> 2.0"

  name                              = "UserDeveloper"
  group_users                       = []
  attach_iam_self_management_policy = true
  custom_group_policy_arns = [
    "arn:aws:iam::aws:policy/AWSSupportAccess",
    aws_iam_policy.manage_parameters.arn,
    aws_iam_policy.LZReadOnlyAccess.arn,
    aws_iam_policy.user_malicious_activity_deny.arn
  ]
}

module "iam_group_with_policies_UserDBA" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-group-with-policies"
  version = "~> 2.0"

  name                              = "UserDBA"
  group_users                       = []
  attach_iam_self_management_policy = true
  custom_group_policy_arns = [
    "arn:aws:iam::aws:policy/AWSSupportAccess",
    aws_iam_policy.manage_parameters.arn,
    aws_iam_policy.dba.arn,
    aws_iam_policy.LZReadOnlyAccess.arn,
    aws_iam_policy.user_malicious_activity_deny.arn
  ]
}

module "iam_group_with_policies_UserTester" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-group-with-policies"
  version = "~> 2.0"

  name                              = "UserTester"
  group_users                       = []
  attach_iam_self_management_policy = true
  custom_group_policy_arns = [
    "arn:aws:iam::aws:policy/AWSSupportAccess",
    aws_iam_policy.manage_parameters.arn,
    aws_iam_policy.LZReadOnlyAccess.arn,
    aws_iam_policy.user_malicious_activity_deny.arn
  ]
}

module "iam_group_with_policies_UserLiveSupport" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-group-with-policies"
  version = "~> 2.0"

  name                              = "UserLiveSupport"
  group_users                       = []
  attach_iam_self_management_policy = true
  custom_group_policy_arns = [
    "arn:aws:iam::aws:policy/AWSSupportAccess",
    aws_iam_policy.LZReadOnlyAccess.arn,
    aws_iam_policy.user_malicious_activity_deny.arn
  ]
}

module "iam_group_with_policies_AuditAdmin" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-group-with-policies"
  version = "~> 2.0"

  name                              = "AuditAdmin"
  group_users                       = []
  attach_iam_self_management_policy = true
  custom_group_policy_arns = [
    "arn:aws:iam::aws:policy/SecurityAudit",
    aws_iam_policy.user_malicious_activity_deny.arn
  ]
}

###################
# Custom Policies #
###################

data "aws_iam_policy_document" "dba" {
  statement {
    effect    = "Allow"
    sid       = "DBA"
    resources = ["*"]
    actions = [
      "rds:StartDBInstance",
      "rds:StopDBInstance",
      "rds:RebootDBInstance",
      "rds:CreateDBSnapshot",
      "rds:DeleteDBSnapshot"
    ]
  }
}

resource "aws_iam_policy" "dba" {
  name   = "user-dba-managed-policy"
  path   = "/"
  policy = data.aws_iam_policy_document.dba.json
}

data "aws_iam_policy_document" "manage_parameters" {
  statement {
    effect    = "Allow"
    resources = ["arn:aws:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter/APP*"]
    actions = [
      "ssm:GetParameter*",
      "ssm:PutParameter",
      "ssm:DeleteParameter",
    ]
  }
  statement {
    effect        = "Deny"
    not_resources = ["arn:aws:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter/APP*"]
    actions = [
      "ssm:GetParameter*",
      "ssm:PutParameter",
      "ssm:DeleteParameter",
    ]
  }
}

resource "aws_iam_policy" "manage_parameters" {
  name   = "user-parameter-store-managed-policy"
  path   = "/"
  policy = data.aws_iam_policy_document.manage_parameters.json
}

data "aws_iam_policy_document" "LZReadOnlyAccess" {
  statement {
    effect    = "Allow"
    resources = ["*"]
    actions = [
      "acm:Describe*",
      "acm:Get*",
      "acm:List*",
      "apigateway:GET",
      "application-autoscaling:Describe*",
      "autoscaling-plans:Describe*",
      "athena:List*",
      "athena:Batch*",
      "athena:Get*",
      "autoscaling:Describe*",
      "cloud9:Describe*",
      "cloud9:List*",
      "cloudformation:Describe*",
      "cloudformation:Get*",
      "cloudformation:List*",
      "cloudformation:Estimate*",
      "cloudformation:Preview*",
      "cloudfront:Get*",
      "cloudfront:List*",
      "cloudhsm:List*",
      "cloudhsm:Describe*",
      "cloudhsm:Get*",
      "cloudsearch:Describe*",
      "cloudsearch:List*",
      "cloudtrail:Describe*",
      "cloudtrail:Get*",
      "cloudtrail:List*",
      "cloudtrail:LookupEvents",
      "cloudwatch:Describe*",
      "cloudwatch:Get*",
      "cloudwatch:List*",
      "codebuild:BatchGet*",
      "codebuild:List*",
      "codecommit:BatchGet*",
      "codecommit:Get*",
      "codecommit:GitPull",
      "codecommit:List*",
      "codedeploy:BatchGet*",
      "codedeploy:Get*",
      "codedeploy:List*",
      "codepipeline:List*",
      "codepipeline:Get*",
      "codestar:List*",
      "codestar:Describe*",
      "codestar:Get*",
      "codestar:Verify*",
      "config:Deliver*",
      "config:Describe*",
      "config:Get*",
      "config:List*",
      "datapipeline:Describe*",
      "datapipeline:EvaluateExpression",
      "datapipeline:Get*",
      "datapipeline:List*",
      "datapipeline:QueryObjects",
      "datapipeline:Validate*",
      "directconnect:Describe*",
      "dms:Describe*",
      "dms:List*",
      "dms:Test*",
      "ds:Check*",
      "ds:Describe*",
      "ds:Get*",
      "ds:List*",
      "ds:Verify*",
      "ec2:Describe*",
      "ec2:Get*",
      "ec2messages:Get*",
      "ecr:BatchCheck*",
      "ecr:BatchGet*",
      "ecr:Describe*",
      "ecr:Get*",
      "ecr:List*",
      "ecs:Describe*",
      "ecs:List*",
      "elasticache:Describe*",
      "elasticache:List*",
      "elasticbeanstalk:Check*",
      "elasticbeanstalk:Describe*",
      "elasticbeanstalk:List*",
      "elasticbeanstalk:Request*",
      "elasticbeanstalk:Retrieve*",
      "elasticbeanstalk:Validate*",
      "elasticfilesystem:Describe*",
      "elasticloadbalancing:Describe*",
      "es:Describe*",
      "es:List*",
      "es:ESHttpGet",
      "es:ESHttpHead",
      "events:Describe*",
      "events:List*",
      "events:Test*",
      "firehose:Describe*",
      "firehose:List*",
      "glacier:List*",
      "glacier:Describe*",
      "glacier:Get*",
      "guardduty:Get*",
      "guardduty:List*",
      "health:Describe*",
      "health:Get*",
      "health:List*",
      "iam:Generate*",
      "iam:Get*",
      "iam:List*",
      "iam:Simulate*",
      "importexport:Get*",
      "importexport:List*",
      "inspector:Describe*",
      "inspector:Get*",
      "inspector:List*",
      "inspector:Preview*",
      "inspector:LocalizeText",
      "kinesisanalytics:Describe*",
      "kinesisanalytics:Discover*",
      "kinesisanalytics:Get*",
      "kinesisanalytics:List*",
      "kinesis:Describe*",
      "kinesis:Get*",
      "kinesis:List*",
      "kms:Describe*",
      "kms:Get*",
      "kms:List*",
      "lambda:List*",
      "lambda:Get*",
      "logs:Describe*",
      "logs:Get*",
      "logs:FilterLogEvents",
      "logs:ListTagsLogGroup",
      "logs:TestMetricFilter",
      "machinelearning:Describe*",
      "machinelearning:Get*",
      "opsworks:Describe*",
      "opsworks:Get*",
      "opsworks-cm:Describe*",
      "organizations:Describe*",
      "organizations:List*",
      "rds:Describe*",
      "rds:List*",
      "rds:Download*",
      "redshift:Describe*",
      "redshift:View*",
      "redshift:Get*",
      "resource-groups:Describe*",
      "resource-groups:Get*",
      "resource-groups:List*",
      "resource-groups:Search*",
      "route53:Get*",
      "route53:List*",
      "route53:Test*",
      "route53domains:Check*",
      "route53domains:Get*",
      "route53domains:List*",
      "route53domains:View*",
      "s3:Get*",
      "s3:List*",
      "s3:Head*",
      "serverlessrepo:List*",
      "serverlessrepo:Get*",
      "serverlessrepo:SearchApplications",
      "servicecatalog:List*",
      "servicecatalog:Scan*",
      "servicecatalog:Search*",
      "servicecatalog:Describe*",
      "ses:Get*",
      "ses:List*",
      "ses:Describe*",
      "ses:Verify*",
      "shield:Describe*",
      "shield:List*",
      "ssm:DescribeParameters",
      "sns:Get*",
      "sns:List*",
      "sns:Check*",
      "sqs:Get*",
      "sqs:List*",
      "sqs:Receive*",
      "states:List*",
      "states:Describe*",
      "states:GetExecutionHistory",
      "storagegateway:Describe*",
      "storagegateway:List*",
      "sts:Get*",
      "swf:Count*",
      "swf:Describe*",
      "swf:Get*",
      "swf:List*",
      "tag:Get*",
      "trustedadvisor:Describe*",
      "waf:Get*",
      "waf:List*",
      "waf-regional:List*",
      "waf-regional:Get*",
      "workspaces:Describe*",
      "xray:BatchGet*",
      "xray:Get*",
    ]
  }
}

resource "aws_iam_policy" "LZReadOnlyAccess" {
  name   = "LZReadOnlyAccess"
  path   = "/"
  policy = data.aws_iam_policy_document.LZReadOnlyAccess.json
}

data "aws_iam_policy_document" "user_malicious_activity_deny" {
  statement {
    effect    = "Deny"
    resources = ["*"]
    actions = [
      "ec2:AcceptVpcPeeringConnection",
      "ec2:AssociateRouteTable",
      "ec2:AttachInternetGateway",
      "ec2:AttachVpnGateway",
      "ec2:AuthorizeSecurityGroupEgress",
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:CreateCustomerGateway",
      "ec2:CreateDhcpOptions",
      "ec2:CreateNatGateway",
      "ec2:CreateNetworkAcl",
      "ec2:CreateNetworkAclEntry",
      "ec2:CreateRoute",
      "ec2:CreateRouteTable",
      "ec2:CreateVpc",
      "ec2:CreateVpcPeeringConnection",
      "ec2:CreateVpnConnection",
      "ec2:CreateVpnConnectionRoute",
      "ec2:CreateVpnGateway",
      "ec2:DeleteCustomerGateway",
      "ec2:DeleteDhcpOptions",
      "ec2:DeleteInternetGateway",
      "ec2:DeleteNatGateway",
      "ec2:DeleteNetworkAcl",
      "ec2:DeleteNetworkAclEntry",
      "ec2:DeleteRoute",
      "ec2:DeleteRouteTable",
      "ec2:DeleteSubnet",
      "ec2:DeleteVpc",
      "ec2:DeleteVpcPeeringConnection",
      "ec2:DeleteVpnConnection",
      "ec2:DeleteVpnConnectionRoute",
      "ec2:DeleteVpnGateway",
      "ec2:DisassociateAddress",
      "ec2:DisassociateRouteTable",
      "ec2:ReplaceNetworkAclAssociation",
      "ec2:ReplaceNetworkAclEntry",
      "ec2:TerminateInstances",
      "cloudtrail:DeleteTrail",
      "cloudtrail:StopLogging",
      "cloudtrail:UpdateTrail",
      "iam:AddRoleToInstanceProfile",
      "iam:AddUserToGroup",
      "iam:AttachGroupPolicy",
      "iam:AttachRolePolicy",
      "iam:AttachUserPolicy",
      "iam:DeleteRole",
      "iam:DeleteRolePolicy",
      "iam:DeleteUserPolicy",
      "iam:PutGroupPolicy",
      "iam:PutRolePolicy",
      "iam:PutUserPolicy",
      "iam:UpdateAssumeRolePolicy",
      "aws-portal:ModifyAccount",
      "aws-portal:ModifyBilling",
      "aws-portal:ModifyPaymentMethods",
      "kms:DeleteAlias",
      "kms:ScheduleKeyDeletion",
      "kms:CreateGrant",
      "kms:PutKeyPolicy",
    ]
  }
}

resource "aws_iam_policy" "user_malicious_activity_deny" {
  name   = "user-malicious-activity-deny-policy"
  path   = "/"
  policy = data.aws_iam_policy_document.user_malicious_activity_deny.json
}

#####################
# Instance Profiles #
#####################

data "aws_iam_policy_document" "instance_profiles_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "instance_profiles_sysadminrole" {
  statement {
    not_actions = ["iam:*"]
    effect  = "Allow"
    resources = ["*"]

    condition {
        test = "BoolIfExists"
        variable = "aws:MultiFactorAuthPresent"
        values = [ "true" ]
    }
  }

  statement {
    effect    = "Deny"
    resources = ["*"]
    actions = [ "aws-portal:*Billing" ]
  }

  statement {
    effect    = "Deny"
    resources = ["*"]
    actions = [ 
        "cloudtrail:DeleteTrail",
        "cloudtrail:StopLogging",
        "cloudtrail:UpdateTrail"
    ]
  }

  statement {
    effect    = "Deny"
    resources = ["*"]
    actions = [ 
        "kms:Create*",
        "kms:Revoke*",
        "kms:Enable*",
        "kms:Get*",
        "kms:Put*",
        "kms:Disable*",
        "kms:Delete*",
        "kms:Update*"
    ]
  }
}

resource "aws_iam_role_policy" "instance_profiles_sysadminrole" {
  name   = "instance_profiles_sysadminrole"
  role   = aws_iam_role.instance_profiles_sysadminrole.id
  policy = data.aws_iam_policy_document.instance_profiles_sysadminrole.json
}

resource "aws_iam_role" "instance_profiles_sysadminrole" {
  name               = "SysAdminRole-inst"
  assume_role_policy = data.aws_iam_policy_document.instance_profiles_assume.json
}

resource "aws_iam_instance_profile" "sysadmin" {
  name = "SysAdminProfile-inst"
  role = aws_iam_role.instance_profiles_sysadminrole.name
}

data "aws_iam_policy_document" "instance_profiles_iam_admin_profile" {
  statement {
    not_actions = ["iam:*"]
    effect  = "Allow"
    resources = ["*"]

    condition {
        test = "BoolIfExists"
        variable = "aws:MultiFactorAuthPresent"
        values = [ "true" ]
    }
  }

  statement {
    effect    = "Deny"
    resources = ["*"]
    actions = [ "aws-portal:*Billing" ]
  }

}

resource "aws_iam_role_policy" "instance_profiles_iam_admin_profile" {
  name   = "instance_profiles_iam_admin_profile"
  role   = aws_iam_role.instance_profiles_iam_admin_profile.id
  policy = data.aws_iam_policy_document.instance_profiles_iam_admin_profile.json
}

resource "aws_iam_role" "instance_profiles_iam_admin_profile" {
  name               = "IAMAdminProfile-inst"
  assume_role_policy = data.aws_iam_policy_document.instance_profiles_assume.json
}

resource "aws_iam_instance_profile" "iam_admin" {
  name = "IAMAdminProfile-inst"
  role = aws_iam_role.instance_profiles_iam_admin_profile.name
}

data "aws_iam_policy_document" "instance_profiles_instance_ops_profile" {
  statement {
    effect    = "Allow"
    resources = ["*"]
    actions = [ "ec2:*" ]
  }
  statement {
    effect    = "Allow"
    resources = ["*"]
    actions = [ "elasticloadbalancing:*" ]
  }
  statement {
    effect    = "Allow"
    resources = ["*"]
    actions = [ "cloudwatch:*" ]
  }
  statement {
    effect    = "Allow"
    resources = ["*"]
    actions = [ "autoscaling:*" ]
  }
  statement {
    effect    = "Deny"
    resources = [ "*" ]
    actions = [ 
        "ec2:CreateVpc*",
        "ec2:DeleteVpc*",
        "ec2:ModifyVpc*",
        "ec2:CreateSubnet*",
        "ec2:DeleteSubnet*",
        "ec2:ModifySubnet*",
        "ec2:Create*Route*",
        "ec2:DeleteRoute*",
        "ec2:AssociateRoute*",
        "ec2:ReplaceRoute*",
        "ec2:CreateVpn*",
        "ec2:DeleteVpn*",
        "ec2:AttachVpn*",
        "ec2:DetachVpn*",
        "ec2:CreateNetworkAcl*",
        "ec2:DeleteNetworkAcl*",
        "ec2:ReplaceNetworkAcl*",
        "ec2:*Gateway*",
        "ec2:*PeeringConnection*"
    ]
  }
  statement {
    effect    = "Deny"
    resources = ["*"]
    actions = [ 
        "kms:Create*",
        "kms:Revoke*",
        "kms:Enable*",
        "kms:Get*",
        "kms:Put*",
        "kms:Disable*",
        "kms:Delete*",
        "kms:Update*"
    ]
  }
}

resource "aws_iam_role_policy" "instance_profiles_instance_ops_profile" {
  name   = "instance_profiles_instance_ops_profile"
  role   = aws_iam_role.instance_profiles_instance_ops.id
  policy = data.aws_iam_policy_document.instance_profiles_instance_ops_profile.json
}

resource "aws_iam_role" "instance_profiles_instance_ops" {
  name               = "InstanceOpsRole-inst"
  assume_role_policy = data.aws_iam_policy_document.instance_profiles_assume.json
}

resource "aws_iam_instance_profile" "instance_ops" {
  name = "rInstanceOpsRole-inst"
  role = aws_iam_role.instance_profiles_instance_ops.name
}






data "aws_iam_policy_document" "instance_profiles_readonly_admin_profile" {
  statement {
    effect    = "Deny"
    resources = ["*"]
    actions = [ "aws-portal:*Billing" ]
  }
  statement {
    effect    = "Allow"
    resources = [ "*" ]
    actions = [ 
        "appstream:Get*",
        "autoscaling:Describe*",
        "cloudformation:DescribeStacks",
        "cloudformation:DescribeStackEvents",
        "cloudformation:DescribeStackResource",
        "cloudformation:DescribeStackResources",
        "cloudformation:GetTemplate",
        "cloudformation:List*",
        "cloudfront:Get*",
        "cloudfront:List*",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudwatch:Describe*",
        "cloudwatch:Get*",
        "cloudwatch:List*",
        "directconnect:Describe*",
        "dynamodb:GetItem",
        "dynamodb:BatchGetItem",
        "dynamodb:Query",
        "dynamodb:Scan",
        "dynamodb:DescribeTable",
        "dynamodb:ListTables",
        "ec2:Describe*",
        "elasticache:Describe*",
        "elasticbeanstalk:Check*",
        "elasticbeanstalk:Describe*",
        "elasticbeanstalk:List*",
        "elasticbeanstalk:RequestEnvironmentInfo",
        "elasticbeanstalk:RetrieveEnvironmentInfo",
        "elasticloadbalancing:Describe*",
        "elastictranscoder:Read*",
        "elastictranscoder:List*",
        "iam:List*",
        "iam:Get*",
        "kinesis:Describe*",
        "kinesis:Get*",
        "kinesis:List*",
        "opsworks:Describe*",
        "opsworks:Get*",
        "route53:Get*",
        "route53:List*",
        "redshift:Describe*",
        "redshift:ViewQueriesInConsole",
        "rds:Describe*",
        "rds:ListTagsForResource",
        "s3:Get*",
        "s3:List*",
        "sdb:GetAttributes",
        "sdb:List*",
        "sdb:Select*",
        "ses:Get*",
        "ses:List*",
        "sns:Get*",
        "sns:List*",
        "sqs:GetQueueAttributes",
        "sqs:ListQueues",
        "sqs:ReceiveMessage",
        "storagegateway:List*",
        "storagegateway:Describe*",
        "trustedadvisor:Describe*"
    ]
  }
}

resource "aws_iam_role_policy" "instance_profiles_readonly_admin_profile" {
  name   = "instance_profiles_readonly_admin_profile"
  role   = aws_iam_role.instance_profiles_readonly_admin_profile.id
  policy = data.aws_iam_policy_document.instance_profiles_readonly_admin_profile.json
}

resource "aws_iam_role" "instance_profiles_readonly_admin_profile" {
  name               = "ReadOnlyAdminRole"
  assume_role_policy = data.aws_iam_policy_document.instance_profiles_assume.json
}

resource "aws_iam_instance_profile" "readonly_admin" {
  name = "rReadOnlyAdminProfile-inst"
  role = aws_iam_role.instance_profiles_readonly_admin_profile.name
}
