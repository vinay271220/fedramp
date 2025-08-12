package terraform.ec2.instance_profile_attached

deny[reason] {
    rc := input.resource_changes[_]
    rc.type == "aws_instance"
    not rc.change.after.iam_instance_profile

    reason := sprintf("EC2 instance %s does not have an IAM instance profile attached", [rc.address])
}
