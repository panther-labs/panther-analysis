from panther_base_helpers import okta_alert_context


def rule(event):
    return event.get("eventType") == "user.authentication.auth_via_IDP"


def title(event):
    target = event.deep_walk(
        "target", "displayName", default="displayName-not-found", return_val="first"
    )
    return (
        f"{event.deep_get('actor', 'displayName', default='<displayName-not-found>')} "
        f"<{event.deep_get('actor', 'alternateId', default='alternateId-not-found')}> "
        f"signed in via 3rd party Identity Provider to {target}"
    )


def alert_context(event):
    return okta_alert_context(event)
