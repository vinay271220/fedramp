package terraform.iam.aws_attached_policy_no_administrative_privileges

deny[reason] {
    rc := input.resource_changes[_]
    rc.type == "aws_iam_policy_attachment"
    is_aws_managed(rc.change.after.policy_arn)
    policy := data.aws_policies[rc.change.after.policy_arn]
    policy_contains_admin(policy)

    reason := sprintf("IAM AWS-managed policy '%s' grants administrative privileges", [rc.change.after.policy_arn])
}

is_aws_managed(arn) {
    startswith(arn, "arn:aws:iam::aws:policy/")
}

policy_contains_admin(policy) {
    policy.Statement[_].Effect == "Allow"
    policy.Statement[_].Action == "*"
    policy.Statement[_].Resource == "*"
}
