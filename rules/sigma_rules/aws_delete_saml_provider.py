def rule(event):
    if all(
        [
            event.deep_get("eventSource", default="") == "iam.amazonaws.com",
            event.deep_get("eventName", default="") == "DeleteSAMLProvider",
            event.deep_get("status", default="") == "success",
        ]
    ):
        return True
    return False
