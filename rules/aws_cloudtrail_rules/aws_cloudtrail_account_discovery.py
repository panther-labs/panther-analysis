from panther_base_helpers import deep_get

DISCOVERY_EVENTS = [
    "GetAlternateContact",
    "GetContactInformation",
    "PutAlternateContact",
    "PutContactInformation",
    "DescribeAccount",
]


def rule(event):
    return event.get("eventName") in DISCOVERY_EVENTS


def title(event):
    return (
        f"User [{deep_get(event, 'userIdentity', 'arn')}]"
        f"performed a [{event.get('eventName')}] "
        f"action in AWS account [{event.get('recipientAccountId')}]."
    )
