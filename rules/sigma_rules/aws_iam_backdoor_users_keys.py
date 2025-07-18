def rule(event):
    if all(
        [
            event.deep_get("eventSource", default="") == "iam.amazonaws.com",
            event.deep_get("eventName", default="") == "CreateAccessKey",
            not "responseElements.accessKey.userName"
            in event.deep_get("userIdentity", "arn", default=""),
        ]
    ):
        return True
    return False
