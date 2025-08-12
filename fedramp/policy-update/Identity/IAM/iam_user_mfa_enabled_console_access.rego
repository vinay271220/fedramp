package terraform..mfa_for_console_users

deny[reason] {
    rc := input.resource_changes[_]
    rc.type == "aws_iam_user"
    rc.change.after.password_enabled == true
    not rc.change.after.mfa_enabled

    reason := sprintf("IAM user '%s' with console access does not have MFA enabled", [rc.name])
}
