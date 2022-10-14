from panther_base_helpers import aws_rule_context, deep_get


def rule(event):
    if event.get("eventName") == "ModifyInstanceAttribute" and deep_get(
        event, "requestParameters", "userData"
    ):
        return True
    return False


def title(event):
    return (
        f"[{deep_get(event,'userIdentity','arn')}] "
        "modified the startup script for "
        f" [{deep_get(event, 'requestParameters', 'instanceId')}] "
        f"in [{event.get('recipientAccountId')}] - [{event.get('awsRegion')}]"
    )


def dedup(event):
    return deep_get(event, "requestParameters", "instanceId")


def alert_context(event):
    return aws_rule_context(event)
