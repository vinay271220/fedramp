package rds_instance_backup_enabled

# Deny if RDS instance has automated backups disabled (BackupRetentionPeriod = 0)
deny[reason] {
    some instance
    rds := input.aws.rds.instances[instance]
    not backups_enabled(rds)
    reason := sprintf("RDS instance '%s' does not have automated backups enabled", [rds.DBInstanceIdentifier])
}

backups_enabled(rds) {
    rds.BackupRetentionPeriod
    rds.BackupRetentionPeriod > 0
}
