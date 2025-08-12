package terraform.guardduty_no_high_severity_findings

# Description: Ensure there are no active GuardDuty findings with high severity.
# This policy assumes you have a data source or plan output listing GuardDuty findings.

violation[{"msg": msg}] {
    some i
    finding := input.guardduty_findings[i]

    # Check if severity is HIGH
    finding.severity == "HIGH"

    # Check if the finding is still active
    finding.status == "ACTIVE"

    msg := sprintf(
        "GuardDuty has an active high severity finding: %s (Type: %s)",
        [finding.id, finding.type]
    )
}
