from panther_base_helpers import aws_rule_context, deep_get


def rule(event):
    # Return True to match the log event and trigger an alert.
    event_names = [
        "CreateTrafficMirrorFilter",
        "CreateTrafficMirrorFilterRule",
        "CreateTrafficMirrorSession",
        "CreateTrafficMirrorTarget",
        "DeleteTrafficMirrorFilter",
        "DeleteTrafficMirrorFilterRule",
        "DeleteTrafficMirrorSession",
        "DeleteTrafficMirrorTarget",
        # "DescribeTrafficMirrorFilters",
        # "DescribeTrafficMirrorSessions",
        # "DescribeTrafficMirrorTargets",
        "ModifyTrafficMirrorFilterNetworkServices",
        "ModifyTrafficMirrorFilterRule",
        "ModifyTrafficMirrorSession",
    ]
    if deep_get(event, "userIdentity", "invokedBy", default="").endswith(".amazonaws.com"):
        return False
    return (
        event.get("eventSource", "") == "ec2.amazonaws.com"
        and event.get("eventName", "") in event_names
    )


def title(event):
    return (
        f"{event.get('userIdentity',{}).get('arn','no-type')} ec2 activity found for "
        f"{event.get('eventName')} in account {event.get('recipientAccountId')} "
        f"in region {event.get('awsRegion')}."
    )


def dedup(event):
    return f"{event.get('userIdentity',{}).get('arn','no-user-identity-provided')}"


def alert_context(event):
    return aws_rule_context(event)
