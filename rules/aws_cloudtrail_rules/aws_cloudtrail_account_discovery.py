DISCOVERY_EVENTS = [
    "GetAlternateContact",
    "GetContactInformation",
    "PutAlternateContact",
    "PutContactInformation",
    "DescribeAccount",
]


def rule(event):
    return event.udm("event_name") in DISCOVERY_EVENTS


def title(event):
    return (
        f"User [{event.udm('user_arn')}]"
        f"performed a [{event.udm('event_name')}] "
        f"action in AWS account [{event.udm('recipient_account_id')}]."
    )
