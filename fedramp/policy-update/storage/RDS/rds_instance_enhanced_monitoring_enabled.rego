package rds.instance.enhanced_monitoring

__rego_metadata__ := {
    "id": "rds_instance_enhanced_monitoring_enabled",
    "title": "RDS instances should have Enhanced Monitoring enabled",
    "description": "Checks whether RDS instances have Enhanced Monitoring configured with a monitoring interval greater than 0 seconds.",
    "version": "1.0.0",
    "severity": "MEDIUM",
    "provider": "aws",
    "service": "rds",
    "category": "Monitoring",
    "resource_type": "aws_db_instance"
}

deny[reason] {
    some i
    instance := input.aws_db_instances[i]
    not enhanced_monitoring_enabled(instance)
    reason := sprintf("RDS instance '%s' does not have Enhanced Monitoring enabled.", [instance.DBInstanceIdentifier])
}

enhanced_monitoring_enabled(instance) {
    instance.MonitoringInterval > 0
}
