##############
# AWS Config #
##############

resource "aws_config_configuration_recorder" "config" {
  name     = "config-example"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "config" {
  name           = "config-example"
  s3_bucket_name = aws_s3_bucket.configlogs.bucket
  sns_topic_arn  = aws_sns_topic.slack_integration.arn

  snapshot_delivery_properties {
    delivery_frequency = "Three_Hours"
  }

  depends_on = [aws_config_configuration_recorder.config]
}

resource "aws_config_configuration_recorder_status" "config" {
  name       = aws_config_configuration_recorder.config.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.config]
}

resource "aws_iam_role" "config" {
  name               = "aws-config-role"
  assume_role_policy = data.aws_iam_policy_document.aws_config_role_policy.json
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSConfigRole"
}

data "aws_iam_policy_document" "aws_config_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    effect = "Allow"
  }
}

# Allow AWS Config Publish in this queue so we get Alerts in Slack
data "aws_iam_policy_document" "allow_config_send_slack_alerts" {
  statement {
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.config.arn]
    }
    actions   = ["SNS:Publish"]
    resources = [aws_sns_topic.slack_integration.arn]
  }
}

resource "aws_sns_topic_policy" "config" {
  arn    = aws_sns_topic.slack_integration.arn
  policy = data.aws_iam_policy_document.allow_config_send_slack_alerts.json
}

#########
# Rules #
#########

resource "aws_config_config_rule" "root_mfa" {
  name = "root-mfa"

  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
  }

  maximum_execution_frequency = "TwentyFour_Hours"

  depends_on = [aws_config_configuration_recorder.config]
}

resource "aws_config_config_rule" "incoming_ssh" {
  name = "unrestricted-ssh-access"

  source {
    owner             = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED"
  }

  depends_on = [aws_config_configuration_recorder.config]
}

resource "aws_config_config_rule" "cloud_trail_enabled" {
  name = "cloudtrail-enabled"

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }

  input_parameters = jsonencode({ "s3BucketName" = "${aws_s3_bucket.cloudtraillogs.id}" })

  depends_on = [aws_config_configuration_recorder.config]
}