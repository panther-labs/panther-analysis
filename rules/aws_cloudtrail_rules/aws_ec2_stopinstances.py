from panther_aws_helpers import aws_rule_context


def rule(event):
    return all(
        [
            not event.get("errorCode"),
            not event.get("errorMessage"),
            event.get("eventName") == "StopInstances",
        ]
    )


def title(event):
    instances = [
        instance["instanceId"]
        for instance in event.deep_get("requestParameters", "instancesSet", "items", default=[])
    ]
    account = event.get("recipientAccountId")
    return f"EC2 instances {instances} stopped in account {account}."


def alert_context(event):
    context = aws_rule_context(event)
    context["instance_ids"] = [
        instance["instanceId"]
        for instance in event.deep_get("requestParameters", "instancesSet", "items", default=[])
    ]
    return context
