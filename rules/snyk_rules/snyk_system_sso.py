from panther_snyk_helpers import snyk_alert_context

ACTIONS = [
    "group.sso.auth0_connection.create",
    "group.sso.auth0_connection.edit",
    "group.sso.create",
    "group.sso.edit",
]


def rule(event):

    action = event.get("event", "<NO_EVENT>")
    return action in ACTIONS


def title(event):
    return (
        "Snyk: System SSO Setting event "
        f"[{event.deep_get('event', default='<NO_EVENT>')}] "
        f"performed by [{event.deep_get('userId', default='<NO_USERID>')}]"
    )


def alert_context(event):
    return snyk_alert_context(event)
