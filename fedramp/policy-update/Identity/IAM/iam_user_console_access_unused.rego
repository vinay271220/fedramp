package terraform.unused_console_access

deny[reason] {
    rc := input.resource_changes[_]
    rc.type == "aws_iam_user"
    rc.change.after.password_enabled == true
    rc.change.after.password_last_used == null

    reason := sprintf("IAM user '%s' has unused console access", [rc.name])
}
