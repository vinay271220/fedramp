package cloudwatch.log_group_retention_policy

# Allowed retention days
allowed_days := {365, 400, 731}  # You can update this set

deny[reason] {
    some log_group
    log_group := input.resource.aws_cloudwatch_log_group[_]
    not log_group_retention_valid(log_group)
    reason := sprintf("CloudWatch Log Group '%s' does not have a valid retention policy (must be one of %v days).", [log_group.name, allowed_days])
}

log_group_retention_valid(log_group) {
    retention := log_group.retention_in_days
    retention != null
    retention != 0
    allowed_days[retention]
}
