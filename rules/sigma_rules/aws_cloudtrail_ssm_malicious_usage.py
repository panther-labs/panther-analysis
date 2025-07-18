def rule(event):
    if all(
        [
            event.deep_get("eventName", default="") == "SendCommand",
            event.deep_get("eventSource", default="") == "ssm.amazonaws.com",
            event.deep_get("responseElements", "command", "status", default="") == "Success",
        ]
    ):
        return True
    return False
