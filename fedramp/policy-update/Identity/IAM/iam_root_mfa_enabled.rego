package terraform.iam.root_mfa_enabled

deny[reason] {
    rc := input.resource_changes[_]
    rc.type == "aws_iam_user"
    rc.name == "root"
    not rc.change.after.mfa_enabled

    reason := "IAM root account does not have MFA enabled"
}
