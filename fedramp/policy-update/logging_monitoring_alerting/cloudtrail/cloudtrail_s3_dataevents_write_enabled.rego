package cloudtrail

# Deny if no S3 data events for write operations are enabled
deny[{"id": "cloudtrail_s3_dataevents_write_enabled", "msg": msg}] {
    some trail in input.aws.cloudtrail.trails
    not trail.is_multi_region_trail
    msg := sprintf("CloudTrail trail %s does not have S3 write data events enabled", [trail.name])
}

# Require at least one S3 write event logging
deny[{"id": "cloudtrail_s3_dataevents_write_enabled", "msg": msg}] {
    some trail in input.aws.cloudtrail.trails
    event_selector := trail.event_selectors[_]
    not s3_write_logging_enabled(event_selector)
    msg := sprintf("CloudTrail trail %s is missing S3 write data events logging", [trail.name])
}

# Helper to check if S3 write events are enabled
s3_write_logging_enabled(event_selector) {
    event_selector.read_write_type == "WriteOnly" 
    some resource in event_selector.data_resources
    resource.type == "AWS::S3::Object"
}
