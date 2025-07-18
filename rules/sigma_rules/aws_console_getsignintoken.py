def rule(event):
    if all(
        [
            event.deep_get("eventSource", default="") == "signin.amazonaws.com",
            event.deep_get("eventName", default="") == "GetSigninToken",
            not "Jersey/${project.version}" in event.deep_get("userAgent", default=""),
        ]
    ):
        return True
    return False
