package dynamodb.tables_pitr_enabled

# Deny if DynamoDB table does not have PITR enabled
deny[reason] {
    some table
    resource := input.resource_changes[table]
    resource.type == "aws_dynamodb_table"
    pitr := resource.change.after.point_in_time_recovery
    not pitr.enabled
    reason := sprintf("DynamoDB table '%s' does not have Point-in-Time Recovery (PITR) enabled.", [resource.change.after.name])
}
