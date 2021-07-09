data "template_file" "aws_config_iam_password_policy" {
  template = file("${path.module}/config-policies/iam-password-policy.tpl")

  vars = {
    # terraform will interpolate boolean as 0/1 and the config parameters expect "true" or "false"
    password_require_uppercase = var.password_require_uppercase ? "true" : "false"
    password_require_lowercase = var.password_require_lowercase ? "true" : "false"
    password_require_symbols   = var.password_require_symbols ? "true" : "false"
    password_require_numbers   = var.password_require_numbers ? "true" : "false"
    password_min_length        = var.password_min_length
    password_reuse_prevention  = var.password_reuse_prevention
    password_max_age           = var.password_max_age
  }
}

# AWS Config Rules
# IAM ----------------------------------------------------------------#

resource "aws_config_organization_managed_rule" "iam-password-policy" {
  count            = var.check_iam_password_policy ? 1 : 0
  name             = "iam-password-policy"
  description      = "Ensure the account password policy for IAM users meets the specified requirements"
  input_parameters = data.template_file.aws_config_iam_password_policy.rendered
  rule_identifier = "IAM_PASSWORD_POLICY"
  
  maximum_execution_frequency = var.config_max_execution_frequency
  depends_on = [aws_config_configuration_recorder.main]
  excluded_accounts = ["097732757849"]
}

resource "aws_config_organization_managed_rule" "iam-user-no-policies-check" {
  count       = var.check_iam_user_no_policies_check ? 1 : 0
  name        = "iam-user-no-policies-check"
  description = "Ensure that none of your IAM users have policies attached. IAM users must inherit permissions from IAM groups or roles."
  rule_identifier = "IAM_USER_NO_POLICIES_CHECK"
  depends_on = [aws_config_configuration_recorder.main]
  excluded_accounts = ["097732757849"]
}

resource "aws_config_organization_managed_rule" "iam-group-has-users-check" {
  count       = var.check_iam_group_has_users_check ? 1 : 0
  name        = "iam-group-has-users-check"
  description = "Checks whether IAM groups have at least one IAM user."
  rule_identifier = "IAM_GROUP_HAS_USERS_CHECK"
  depends_on = [aws_config_configuration_recorder.main]
  excluded_accounts = ["097732757849"]
}

resource "aws_config_organization_managed_rule" "mfa_enabled_for_iam_console_access" {
  count = var.check_mfa_enabled_for_iam_console_access ? 1 : 0

  name        = "mfa-enabled-for-iam-console-access"
  description = "Checks whether AWS Multi-Factor Authentication (MFA) is enabled for all AWS Identity and Access Management (IAM) users that use a console password. The rule is compliant if MFA is enabled."
  rule_identifier = "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS"
  depends_on = [aws_config_configuration_recorder.main]
  excluded_accounts = ["097732757849"]
}


# IAM \----------------------------------------------------------------#
#---------------S3-----------------------------------------------------#

resource "aws_config_organization_managed_rule" "s3-bucket-public-write-prohibited" {
  count       = var.check_s3_bucket_public_write_prohibited ? 1 : 0
  name        = "s3-bucket-public-write-prohibited"
  description = "Checks that your S3 buckets do not allow public write access."
  rule_identifier = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"

  depends_on = [aws_config_configuration_recorder.main]
  excluded_accounts = ["097732757849"]
}


resource "aws_config_organization_managed_rule" "iam_root_access_key" {
  count = var.check_iam_root_access_key ? 1 : 0

  name        = "iam-root-access-key"
  description = "Checks whether the root user access key is available. The rule is COMPLIANT if the user access key does not exist"

  rule_identifier = "IAM_ROOT_ACCESS_KEY_CHECK"


  depends_on = [aws_config_configuration_recorder.main]
  excluded_accounts = ["097732757849"]
}


resource "aws_config_organization_managed_rule" "s3_bucket_ssl_requests_only" {
  count = var.check_s3_bucket_ssl_requests_only ? 1 : 0

  name        = "s3-bucket-ssl-requests-only"
  description = "Checks whether S3 buckets have policies that require requests to use Secure Socket Layer (SSL)."
  rule_identifier = "S3_BUCKET_SSL_REQUESTS_ONLY"

  depends_on = [aws_config_configuration_recorder.main]
  excluded_accounts = ["097732757849"]
}
#----------------s3\
#-----------------DynamoDB-------------------------#

resource "aws_config_organization_managed_rule" "dynamodb_autoscaling_enabled" {
  count = var.check_s3_bucket_ssl_requests_only ? 1 : 0

  name        = "dynamodb_autoscaling_enabled"
  description = "This rule checks whether Auto Scaling is enabled on your DynamoDB tables. Optionally you can set the read and write capacity units for the table."
  rule_identifier = "DYNAMODB_AUTOSCALING_ENABLED"

  depends_on = [aws_config_configuration_recorder.main]
  excluded_accounts = ["097732757849"]
}

resource "aws_config_organization_managed_rule" "dynamodb_throughput_limit_check" {
  count = var.check_s3_bucket_ssl_requests_only ? 1 : 0

  name        = "dynamodb_throughput_limit_check"
  description = "Checks whether provisioned DynamoDB throughput is approaching the maximum limit for your account."
  rule_identifier = "DYNAMODB_THROUGHPUT_LIMIT_CHECK"

  depends_on = [aws_config_configuration_recorder.main]
  excluded_accounts = ["097732757849"]
}

#-----------------Operational-Best-Practices-for-Encryption-and-Keys-------------------------#
# resource "aws_config_organization_managed_rule" "dynamodb_throughput_limit_check" {
#   count = var.check_s3_bucket_ssl_requests_only ? 1 : 0

#   name        = "dynamodb_throughput_limit_check"
#   description = "Checks whether provisioned DynamoDB throughput is approaching the maximum limit for your account."
#   rule_identifier = "DYNAMODB_THROUGHPUT_LIMIT_CHECK"

#   depends_on = [aws_config_configuration_recorder.main]
#   excluded_accounts = ["097732757849"]
# }



#aws configservice describe-organization-conformance-packs --organization-conformance-pack-name=OrgS3ConformancePack