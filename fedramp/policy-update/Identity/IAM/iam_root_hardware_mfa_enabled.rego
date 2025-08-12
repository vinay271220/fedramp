package terraform.root_hardware_mfa_enabled

deny[reason] {
    rc := input.resource_changes[_]
    rc.type == "aws_iam_user"
    rc.name == "root"
    not rc.change.after.has_hardware_mfa

    reason := "Root account does not have hardware MFA enabled"
}
