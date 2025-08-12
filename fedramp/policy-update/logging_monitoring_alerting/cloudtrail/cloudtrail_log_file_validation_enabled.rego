package cloudtrail

default cloudtrail_log_file_validation_enabled = false

cloudtrail_log_file_validation_enabled {
    some trail
    trail := input.cloudtrail_trails[_]
    trail.LogFileValidationEnabled == true
}
