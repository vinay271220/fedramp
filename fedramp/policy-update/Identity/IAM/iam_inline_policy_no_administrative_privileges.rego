package terraform.iam.inline_policy_no_administrative_privileges

deny[reason] {
    rc := input.resource_changes[_]
    rc.type == "aws_iam_user_policy"  # could also be aws_iam_role_policy or aws_iam_group_policy
    policy := rc.change.after.policy
    policy_contains_admin(policy)

    reason := sprintf("IAM inline policy for '%s' grants administrative privileges", [rc.change.after.user])
}

policy_contains_admin(policy) {
    policy.Statement[_].Effect == "Allow"
    policy.Statement[_].Action == "*"
    policy.Statement[_].Resource == "*"
}
