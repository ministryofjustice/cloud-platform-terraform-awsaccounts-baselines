
#########
# rules #
#########

resource "aws_cloudwatch_event_rule" "dlm_state" {
  count = var.enable_cloudwatch ? 1 : 0

  name        = "dlm_policy_state"
  description = "DLM Policy State Change"

  event_pattern = <<PATTERN
        {
  "source": [
    "aws.dlm"
  ],
  "detail-type": [
    "DLM Policy State Change"
  ],
  "detail": {
    "state": [
      "ERROR"
    ]
  }
}
PATTERN

}

resource "aws_cloudwatch_event_target" "dlm_sns" {
  count = var.enable_cloudwatch ? 1 : 0

  rule      = aws_cloudwatch_event_rule.dlm_state.0.name
  target_id = "SendToSNS"
  arn       = var.slack_topic_arn
}
