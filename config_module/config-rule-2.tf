data "template_file" "acm_certificate_expiration_check" {
  template = file("${path.module}/config-policies/acm-certificate-expiration-check.tpl")
  vars = {
    "days_to_expiration" = var.days_to_expiration
  }
}



resource "aws_config_organization_managed_rule" "acm-certificate-expiration-check" {
  count = var.check_s3_bucket_ssl_requests_only ? 1 : 0

  name        = "acm-certificate-expiration-check"
  description = "acm certificate expiration check"
  rule_identifier = "ACM_CERTIFICATE_EXPIRATION_CHECK"
 # input_parameters = data.template_file.acm_certificate_expiration_check.rendered

  depends_on = [aws_config_configuration_recorder.main]
  excluded_accounts = ["097732757849"]
}

resource "aws_config_organization_managed_rule" "alb-http-to-https-redirection-check" {
  count = var.check_s3_bucket_ssl_requests_only ? 1 : 0

  name        = "alb-http-to-https-redirection-check"
  description = "alb http to https redirection check"
  rule_identifier = "ALB_HTTP_TO_HTTPS_REDIRECTION_CHECK"
 # input_parameters = data.template_file.acm_certificate_expiration_check.rendered

  depends_on = [aws_config_configuration_recorder.main]
  excluded_accounts = ["097732757849"]
}
