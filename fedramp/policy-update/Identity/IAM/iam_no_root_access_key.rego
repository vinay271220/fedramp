package terraform.no_root_access_keys

deny[reason] {
    rc := input.resource_changes[_]
    rc.type == "aws_iam_access_key"
    rc.change.after.user == "root"

    reason := "Root account has active access keys"
}
