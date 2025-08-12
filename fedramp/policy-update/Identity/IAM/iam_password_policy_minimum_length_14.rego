package iam_password_policy_minimum_length_14

# Deny if any violations exist
deny[reason] {
  input.resource_changes[_] as rc
  rc.type == "aws_iam_account_password_policy"
  rc.change.after.minimum_password_length < 14
  reason := "Password policy must have minimum length 14 (AC-2(1))"
}