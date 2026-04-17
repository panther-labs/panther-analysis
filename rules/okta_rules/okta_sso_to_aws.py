def rule(event):
    return all(
        [
            event.get("eventType") == "user.authentication.sso",
            event.deep_get("outcome", "result") == "SUCCESS",
            "AWS IAM Identity Center" in event.deep_walk("target", "displayName", default=[]),
        ]
    )


def alert_context(event):
    return {
        "actor": event.deep_get("actor", "alternateId", default="").split("@")[0],
    }
