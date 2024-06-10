def rule(event):
    return event.deep_get("eventType") == "user.session.start"


def title(event):
    return f'{event.deep_get("actor", "displayName")} logged in to Okta'
