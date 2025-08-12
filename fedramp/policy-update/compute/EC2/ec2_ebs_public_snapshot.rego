package terraform.ec2.ebs_public_snapshot

deny[reason] {
    rc := input.resource_changes[_]
    rc.type == "aws_ebs_snapshot"
    rc.change.after_create_volume_permission[_] == "all"

    reason := sprintf("EBS snapshot %s is public", [rc.address])
}
