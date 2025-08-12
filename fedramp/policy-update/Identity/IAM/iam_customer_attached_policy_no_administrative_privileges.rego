package terraform.iam.customer_attached_policy_no_administrative_privileges

deny[reason] {
    rc := input.resource_changes[_]
    rc.type == "aws_iam_policy"
    not is_aws_managed(rc.arn)
    policy := rc.change.after.policy_document
    policy_contains_admin(policy)

    reason := sprintf("IAM customer-managed policy '%s' grants administrative privileges", [rc.name])
}

is_aws_managed(arn) {
    startswith(arn, "arn:aws:iam::aws:policy/")
}

policy_contains_admin(policy) {
    policy.Statement[_].Effect == "Allow"
    policy.Statement[_].Action == "*"
    policy.Statement[_].Resource == "*"
}
