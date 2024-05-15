from panther_base_helpers import aws_rule_context


def rule(event):
    return (
        event.udm("event_source") == "ec2.amazonaws.com"
        and event.udm("event_name") == "DisableEbsEncryptionByDefault"
    )


def title(event):
    return (
        "EC2 EBS Default Encryption was disabled in "
        f"[{event.udm('recipient_account_id')}] - "
        f"[{event.udm('cloud_region')}]"
    )


def alert_context(event):
    return aws_rule_context(event)
