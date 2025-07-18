def rule(event):
    if all(
        [
            event.deep_get("eventSource", default="") == "guardduty.amazonaws.com",
            event.deep_get("eventName", default="") == "CreateIPSet",
        ]
    ):
        return True
    return False
