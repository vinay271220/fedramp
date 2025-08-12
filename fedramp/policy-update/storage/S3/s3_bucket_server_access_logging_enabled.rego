package s3_bucket_server_access_logging_enabled

# Description: Ensure S3 buckets have server access logging enabled.
deny[msg] {
    some bucket
    bucket.logging.enabled == false
    msg := sprintf("S3 Bucket '%s' does not have server access logging enabled", [bucket.name])
}
