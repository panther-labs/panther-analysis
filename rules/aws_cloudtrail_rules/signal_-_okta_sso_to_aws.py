def rule(event):
    # Return True to match the log event and trigger an alert.
    return all(
        [
            event.get("eventType") == "user.authentication.sso",
            event.deep_get("outcome", "result") == "SUCCESS",
            "AWS IAM Identity Center" in event.deep_walk("target", "displayName"),
        ]
    )