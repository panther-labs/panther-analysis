def rule(event):
    if all(
        [
            event.deep_get("eventSource", default="") == "sts.amazonaws.com",
            event.deep_get("eventName", default="") == "GetSessionToken",
            event.deep_get("userIdentity", "type", default="") == "IAMUser",
        ]
    ):
        return True
    return False
