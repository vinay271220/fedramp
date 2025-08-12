package policy.kms_cmk_rotation_enabled

deny[reason] {
    some key
    aws_kms_keys[key]
    not aws_kms_keys[key].rotation_enabled
    reason := sprintf("KMS CMK '%s' does not have key rotation enabled", [aws_kms_keys[key].arn])
}

# Mock input example for testing
aws_kms_keys = {
    "key1": {
        "arn": "arn:aws:kms:us-east-1:123456789012:key/abc123",
        "rotation_enabled": false
    },
    "key2": {
        "arn": "arn:aws:kms:us-east-1:123456789012:key/xyz789",
        "rotation_enabled": true
    }
}
