package cloudtrail_multi_region_enabled

# Policy to ensure that AWS CloudTrail is enabled in all regions.

deny[reason] {
    some trail
    input.trails[trail]
    not input.trails[trail].IsMultiRegionTrail
    reason := sprintf("CloudTrail '%s' is not enabled for all regions (multi-region disabled)", [input.trails[trail].Name])
}
