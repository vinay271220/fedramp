package terraform.policy_only_groups_roles

deny[reason] {
    rc := input.resource_changes[_]
    rc.type == "aws_iam_policy_attachment"
    some u
    rc.change.after.users[u] != ""

    reason := sprintf("CM-5(1)(a): IAM policy '%s' attached directly to a user", [rc.name])
}
