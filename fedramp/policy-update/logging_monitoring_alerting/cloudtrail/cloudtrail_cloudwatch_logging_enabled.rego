package cloudtrail

# Policy to check if CloudTrail is configured to send logs to CloudWatch Logs
default cloudtrail_cloudwatch_logging_enabled = false

cloudtrail_cloudwatch_logging_enabled {
    some trail
    input.trails[trail]
    input.trails[trail].CloudWatchLogsLogGroupArn != ""
    input.trails[trail].CloudWatchLogsRoleArn != ""
}
