package rds_instance_multi_az

# Deny if RDS instance does not have Multi-AZ enabled
deny[reason] {
    some instance
    rds := input.aws.rds.instances[instance]
    not rds.MultiAZ
    reason := sprintf("RDS instance '%s' does not have Multi-AZ enabled", [rds.DBInstanceIdentifier])
}
