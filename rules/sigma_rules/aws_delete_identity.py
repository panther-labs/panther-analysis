def rule(event):
    if all(
        [
            event.deep_get("eventSource", default="") == "ses.amazonaws.com",
            event.deep_get("eventName", default="") == "DeleteIdentity",
        ]
    ):
        return True
    return False
