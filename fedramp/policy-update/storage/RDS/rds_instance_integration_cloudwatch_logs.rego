package rds_instance_integration_cloudwatch_logs

# Deny if an RDS instance does not have CloudWatch Logs enabled
deny[msg] {
    some i
    resource := input.resource_changes[i]
    resource.type == "aws_db_instance"
    resource.change.after.enabled_cloudwatch_logs_exports == []

    msg := sprintf(
        "RDS instance %q does not have CloudWatch log exports enabled.",
        [resource.name]
    )
}

# Deny if CloudWatch logs exports attribute is missing entirely
deny[msg] {
    some i
    resource := input.resource_changes[i]
    resource.type == "aws_db_instance"
    not resource.change.after.enabled_cloudwatch_logs_exports

    msg := sprintf(
        "RDS instance %q has no CloudWatch log export configuration.",
        [resource.name]
    )
}
