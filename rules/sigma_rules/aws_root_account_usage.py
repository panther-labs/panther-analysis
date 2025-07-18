def rule(event):
    if all(
        [
            event.deep_get("userIdentity", "type", default="") == "Root",
            not event.deep_get("eventType", default="") == "AwsServiceEvent",
        ]
    ):
        return True
    return False
