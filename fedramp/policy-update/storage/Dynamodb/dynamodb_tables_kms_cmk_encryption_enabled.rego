package dynamodb_tables_kms_cmk_encryption_enabled

deny[reason] {
    some table
    tbl := input.aws.dynamodb.tables[table]

    not tbl.SSEDescription
    reason := sprintf("DynamoDB table '%s' has no server-side encryption configured", [tbl.TableName])
}

deny[reason] {
    some table
    tbl := input.aws.dynamodb.tables[table]

    tbl.SSEDescription
    tbl.SSEDescription.Status == "ENABLED"
    tbl.SSEDescription.SSEType == "KMS"

    # Must not be using AWS-owned CMK
    tbl.SSEDescription.KMSMasterKeyArn == ""
    reason := sprintf("DynamoDB table '%s' is using AWS-owned KMS key instead of a custom
