package aws.guardduty_enabled

# Deny if GuardDuty detector is not enabled
deny[reason] {
    not guardduty_enabled
    reason := "Amazon GuardDuty is not enabled in this AWS account."
}

# Helper rule: true if at least one GuardDuty detector is enabled
guardduty_enabled {
    some i
    resource := input.resource_changes[i]
    resource.type == "aws_guardduty_detector"
    resource.change.after.enable == true
}
