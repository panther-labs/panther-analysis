from panther_base_helpers import aws_rule_context


def rule(event):
    if event.get("eventName") == "ModifyInstanceAttribute" and event.deep_get(
        "requestParameters", "userData"
    ):
        return True
    return False


def title(event):
    return (
        f"[{event.deep_get('userIdentity','arn')}] "
        "modified the startup script for "
        f" [{event.deep_get('requestParameters', 'instanceId')}] "
        f"in [{event.get('recipientAccountId')}] - [{event.get('awsRegion')}]"
    )


def dedup(event):
    return event.deep_get("requestParameters", "instanceId")


def alert_context(event):
    context = aws_rule_context(event)
    context["instance_ids"] = [event.deep_get("requestParameters", "instanceId"), "no_instance_id"]
    return context
