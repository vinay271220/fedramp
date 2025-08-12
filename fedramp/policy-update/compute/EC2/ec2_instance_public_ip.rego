package terraform.ec2.instance_public_ip

deny[reason] {
    rc := input.resource_changes[_]
    rc.type == "aws_instance"
    rc.change.after.associate_public_ip_address == true

    reason := sprintf("EC2 instance %s has a public IP address associated", [rc.address])
}
