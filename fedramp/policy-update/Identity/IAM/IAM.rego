package fedramp.iam

# Deny if any violations exist
deny[reason] {
  input.resource_changes[_] as rc
  rc.type == "aws_iam_account_password_policy"
  rc.change.after.minimum_password_length < 14
  reason := "Password policy must have minimum length 14 (AC-2(1))"
}

deny[reason] {
  input.resource_changes[_] as rc
  rc.type == "aws_iam_user_policy_attachment"
  rc.change.after.policy_arn == "arn:aws:iam::aws:policy/AdministratorAccess"
  reason := "Users cannot have AdministratorAccess directly attached (AC-2(1))"
}

deny[reason] {
  input.resource_changes[_] as rc
  rc.type == "aws_iam_user"
  not rc.change.after.mfa_enabled
  reason := sprintf("IAM user %v must have MFA enabled for console access (AC-2(1))", [rc.name])
}

deny[reason] {
  input.resource_changes[_] as rc
  rc.type == "aws_iam_access_key"
  rc.change.after.status == "Active"
  rc.change.after.last_used == null
  reason := sprintf("IAM Access Key for user %v must not be unused (AC-2(1))", [rc.change.after.user])
}

deny[reason] {
  input.resource_changes[_] as rc
  rc.type == "aws_iam_user_policy"
  contains(rc.change.after.policy, "\"Action\": \"*\"")
  contains(rc.change.after.policy, "\"Resource\": \"*\"")
  reason := sprintf("Inline IAM policy for user %v grants administrative privileges (AC-2(1))", [rc.change.after.user])
}
