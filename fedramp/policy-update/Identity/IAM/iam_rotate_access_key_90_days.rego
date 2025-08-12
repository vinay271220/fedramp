package terraform.access_keys_rotated_90_days

deny[reason] {
    rc := input.resource_changes[_]
    rc.type == "aws_iam_access_key"
    last_rotated := time.parse_rfc3339(rc.change.after.create_date)
    age_days := (time.now_ns() - last_rotated) / 1000000000 / 86400
    age_days > 90

    reason := sprintf("IAM access key for user '%s' is older than 90 days", [rc.change.after.user])
}
