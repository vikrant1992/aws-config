module "config" {
    source = "./config_module"
    config_name = "aws-config"
    aggregate_organization = true
    config_logs_bucket = "config-bucket-495176261960"
}