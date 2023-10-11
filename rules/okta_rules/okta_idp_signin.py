from panther_base_helpers import deep_get, deep_walk, okta_alert_context


def rule(event):
    return event.get("eventType") == "user.authentication.auth_via_IDP"


def title(event):
    target = deep_walk(
        event, "target", "displayName", default="displayName-not-found", return_val="first"
    )
    return (
        f"{deep_get(event, 'actor', 'displayName', default='<displayName-not-found>')} "
        f"<{deep_get(event, 'actor', 'alternateId', default='alternateId-not-found')}> "
        f"signed in via 3rd party Identity Provider to {target}"
    )


def alert_context(event):
    return okta_alert_context(event)
