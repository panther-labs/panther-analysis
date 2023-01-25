from panther_base_helpers import deep_get, aws_rule_context

DISCOVERY_EVENTS = [
    "DescribeRegionSettings",
    "DescribeRegions",
    "GetRegions",
    "ListResources",
    "DescribeSourceRegions",
]


def rule(event):
    return event.get("eventName") in DISCOVERY_EVENTS


def title(event):
    return (
        f"User [{deep_get(event, 'userIdentity', 'principalId')}] "
        f"performed a [{event.get('eventName')}] "
        f"action in AWS account [{event.get('recipientAccountId')}]."
    )


def alert_context(event):
    return aws_rule_context(event)
