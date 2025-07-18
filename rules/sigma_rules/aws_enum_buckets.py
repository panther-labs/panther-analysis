def rule(event):
    if all(
        [
            event.deep_get("eventSource", default="") == "s3.amazonaws.com",
            event.deep_get("eventName", default="") == "ListBuckets",
            not event.deep_get("userIdentity", "type", default="") == "AssumedRole",
        ]
    ):
        return True
    return False
