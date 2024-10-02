from panther_base_helpers import aws_rule_context


def rule(event):
    return (
        event.get("eventSource") == "ec2.amazonaws.com"
        and event.get("eventName") == "ModifySnapshotAttribute"
    )


def title(event):
    return (
        f"[{event.deep_get('userIdentity','arn')}] "
        "modified snapshot attributes for "
        f"[{event.deep_get('requestParameters','snapshotId')}] "
        f"in [{event.get('recipientAccountId')}] - [{event.get('awsRegion')}]."
    )


def alert_context(event):
    return aws_rule_context(event)
