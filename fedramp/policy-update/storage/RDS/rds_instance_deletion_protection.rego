package rds_instance_deletion_protection

# Deny if RDS instance deletion protection is not enabled
deny[reason] {
    some instance
    aws_rds_instances[instance]
    not instance_has_deletion_protection(instance)
    reason := sprintf("RDS instance '%s' does not have deletion protection enabled.", [instance.db_instance_identifier])
}

# Helper function to check deletion protection
instance_has_deletion_protection(instance) {
    instance.deletion_protection == true
}

# Mock input for testing
aws_rds_instances := input.aws.rds.instances
