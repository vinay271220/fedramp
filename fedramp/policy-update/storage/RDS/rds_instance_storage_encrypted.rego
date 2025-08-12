package rds_instance_storage_encrypted

__rego_metadata__ := {
    "id": "rds_instance_storage_encrypted",
    "title": "Ensure RDS instances have storage encryption enabled",
    "description": "RDS instances should have storage encryption enabled to protect data at rest.",
    "severity": "High",
    "version": "1.0.0"
}

# Rule: Deny RDS instances without storage encryption
deny[reason] {
    some instance
    instance := input.aws.rds.instances[_]
    not instance.StorageEncrypted
    reason := sprintf("RDS instance '%s' does not have storage encryption enabled.", [instance.DBInstanceIdentifier])
}
