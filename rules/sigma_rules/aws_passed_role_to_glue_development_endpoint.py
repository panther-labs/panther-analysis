def rule(event):
    if all(
        [
            event.deep_get("eventSource", default="") == "glue.amazonaws.com",
            event.deep_get("eventName", default="")
            in ["CreateDevEndpoint", "DeleteDevEndpoint", "UpdateDevEndpoint"],
        ]
    ):
        return True
    return False
