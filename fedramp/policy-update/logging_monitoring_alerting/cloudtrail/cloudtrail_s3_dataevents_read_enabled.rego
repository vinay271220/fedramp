package cloudtrail_s3_dataevents_read_enabled

# Ensure CloudTrail is logging S3 read data events

deny[reason] {
    some trail
    input.trails[trail]
    not s3_read_logging_enabled(input.trails[trail])
    reason := sprintf("CloudTrail '%s' is not logging S3 data events for read actions", [input.trails[trail].Name])
}

# Helper: checks if S3 read data events are enabled
s3_read_logging_enabled(trail) {
    some event_selector
    trail.EventSelectors[event_selector]
    trail.EventSelectors[event_selector].DataResources[_].Type == "AWS::S3::Object"
    trail.EventSelectors[event_selector].ReadWriteType == "ReadOnly"
}
