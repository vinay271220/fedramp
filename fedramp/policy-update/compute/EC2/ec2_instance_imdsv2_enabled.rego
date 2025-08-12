package terraform.ec2.instance_imdsv2_enabled

deny[reason] {
    rc := input.resource_changes[_]
    rc.type == "aws_instance"

    meta_opts := rc.change.after.metadata_options
    not meta_opts.http_tokens
    reason := sprintf("EC2 instance %s does not have IMDSv2 enabled (http_tokens not set)", [rc.address])

} else {
    rc := input.resource_changes[_]
    rc.type == "aws_instance"

    meta_opts := rc.change.after.metadata_options
    meta_opts.http_tokens != "required"
    reason := sprintf("EC2 instance %s does not require IMDSv2 (http_tokens != 'required')", [rc.address])
}
