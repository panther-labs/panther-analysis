EVENT_NAMES = [
    "StopLogging",
    "UpdateTrail",
    "DeleteTrail",
]


def rule(event):
    does_event_name_match: bool = event.get("eventName") in EVENT_NAMES

    if does_event_name_match:
        return True
    return False


def title(event):
    return (
        f"User [{event.deep_get('userIdentity', 'arn')}]"
        f"performed a [{event.get('eventName')}] "
        f"action in AWS account [{event.get('recipientAccountId')}]."
    )
