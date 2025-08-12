package rds_snapshots_public_access

# Deny if any snapshot is shared with the 'all' group (public)
deny[reason] {
    some snapshot
    snap := input.aws_rds_snapshots[snapshot]
    snap.public == true
    reason := sprintf("RDS snapshot '%s' is publicly accessible", [snapshot])
}
