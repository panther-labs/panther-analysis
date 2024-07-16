def rule(event):
    return (
        event.deep_get("eventType") == "user.session.start"
        and event.deep_get("outcome", "result") == "SUCCESS"
    )


def title(event):
    return f'{event.deep_get("actor", "displayName")} logged in to Okta'
