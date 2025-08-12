package fedramp.secretsmanager

deny[reason] {
  input.resource_changes[_] as rc
  rc.type == "aws_secretsmanager_secret"
  not rc.change.after.rotation_enabled
  reason := sprintf("Secret %v must have automatic rotation enabled (AC-2(1))", [rc.name])
}
