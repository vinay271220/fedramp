package cloudwatch_changes_to_network_route_tables_alarm_configured

default allow = false

allow {
    some alarm
    input.cloudwatch_alarms[alarm].metric_name == "AWS/EC2"
    input.cloudwatch_alarms[alarm].filter_pattern contains "AWS::EC2::RouteTable"
    input.cloudwatch_alarms[alarm].enabled == true
}
