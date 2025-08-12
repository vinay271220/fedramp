package terraform.iam.unused_access_keys

deny[reason] {
    rc := input.resource_changes[_]
    rc.type == "aws_iam_access_key"
    rc.change.after.status == "Active"
    rc.change.after.last_used == null

    reason := sprintf("IAM access key for user '%s' is unused", [rc.change.after.user])
}
