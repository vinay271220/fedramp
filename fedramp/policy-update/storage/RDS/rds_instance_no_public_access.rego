package rds_instance_no_public_access

# Deny if any RDS instance is publicly accessible
deny[reason] {
    some instance
    rds := input.aws_rds_instances[instance]
    rds.publicly_accessible == true
    reason := sprintf("RDS instance '%s' has public accessibility enabled", [instance])
}
