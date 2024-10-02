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
        f"User [{event.deep_get('userIdentity', 'arn')}]"
        f"performed a [{event.get('eventName')}] "
        f"action in AWS account [{event.get('recipientAccountId')}]."
    )
