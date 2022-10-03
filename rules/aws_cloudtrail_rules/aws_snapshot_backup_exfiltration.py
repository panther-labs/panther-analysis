from panther_base_helpers import aws_rule_context, deep_get


def rule(event):
    return (
        event.get("eventSource") == "ec2.amazonaws.com"
        and event.get("eventName") == "ModifySnapshotAttribute"
    )


def title(event):
    return (
        f"[{deep_get(event,'userIdentity','arn')}] "
        "modified snapshot attributes for "
        f"[{deep_get(event,'requestParameters','snapshotId')}]"
    )


def alert_context(event):
    return aws_rule_context(event)
