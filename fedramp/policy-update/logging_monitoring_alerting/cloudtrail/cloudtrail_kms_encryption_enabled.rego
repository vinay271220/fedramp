package cloudtrail

# Deny if KMS encryption is not enabled for CloudTrail
deny[reason] {
    some trail
    trail := input.cloudtrail_trails[_]

    # cloudtrail_kms_key_id should exist and not be empty
    not trail.kms_key_id
    reason := sprintf("CloudTrail '%s' does not have KMS encryption enabled.", [trail.name])
}
