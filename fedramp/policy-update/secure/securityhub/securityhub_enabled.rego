package terraform.securityhub_enabled

__rego_metadata__ := {
    "id": "securityhub_enabled",
    "title": "Security Hub must be enabled",
    "description": "Ensures AWS Security Hub is enabled in the account.",
    "custom": {
        "severity": "High",
        "provider": "AWS",
        "service": "Security Hub"
    }
}

deny[reason] {
    some i
    resource := input.resource_changes[i]
    resource.type == "aws_securityhub_account"
    resource.change.after == null
    reason := sprintf("AWS Security Hub is not enabled for resource %s", [resource.address])
}

deny[reason] {
    not any_securityhub_enabled
    reason := "No AWS Security Hub account is enabled in the plan."
}

any_securityhub_enabled {
    some i
    resource := input.resource_changes[i]
    resource.type == "aws_securityhub_account"
    resource.change.after != null
}
