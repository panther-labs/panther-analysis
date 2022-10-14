from panther_base_helpers import aws_rule_context


def rule(event):
    return (
        event.get("eventSource") == "ec2.amazonaws.com"
        and event.get("eventName") == "DisableEbsEncryptionByDefault"
    )


def title(event):
    return (
        "EC2 EBS Default Encryption was disabled in "
        f"[{event.get('recipientAccountId')}] - "
        f"[{event.get('awsRegion')}]"
    )


def alert_context(event):
    return aws_rule_context(event)
