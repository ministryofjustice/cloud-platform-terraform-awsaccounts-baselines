resource "aws_accessanalyzer_analyzer" "example" {
  analyzer_name = var.access_analyzer_name

  tags = var.tags
}
