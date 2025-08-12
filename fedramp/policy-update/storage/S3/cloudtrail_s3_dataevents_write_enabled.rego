package cloudtrail_s3_dataevents_write_enabled

# Description: Ensure CloudTrail is logging S3 Data Events for Write operations.
deny[msg] {
    some trail
    not s3_dataevents_write_enabled(trail)
    msg := sprintf("CloudTrail '%s' is not logging S3 Data Events for Write operations", [trail.name])
}

s3_dataevents_write_enabled(trail) {
    trail.eventSelectors[_].dataResources[_] == {
        "type": "AWS::S3::Object",
        "values": ["arn:aws:s3:::"]
    }
    trail.eventSelectors[_].readWriteType == "WriteOnly"
}
