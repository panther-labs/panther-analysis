from panther_base_helpers import deep_get, okta_alert_context


def rule(event):
    return (
        event.get("eventType") == "user.authentication.auth_via_mfa"
        and deep_get(event, "outcome", "result") == "FAILURE"
        and deep_get(event, "outcome", "reason") == "FastPass declined phishing attempt"
    )


def title(event):
    return (
        f"{deep_get(event, 'actor', 'displayName', default='<displayName-not-found>')} "
        f"<{deep_get(event, 'actor', 'alternateId', default='alternateId-not-found')}> "
        f"FastPass declined phishing attempt"
    )


def alert_context(event):
    return okta_alert_context(event)
