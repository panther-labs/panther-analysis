from panther_okta_helpers import okta_alert_context


def rule(event):
    return (
        event.get("eventType") == "user.authentication.auth_via_mfa"
        and event.deep_get("outcome", "result") == "FAILURE"
        and event.deep_get("outcome", "reason") == "FastPass declined phishing attempt"
    )


def title(event):
    return (
        f"{event.deep_get('actor', 'displayName', default='<displayName-not-found>')} "
        f"<{event.deep_get('actor', 'alternateId', default='alternateId-not-found')}> "
        f"FastPass declined phishing attempt"
    )


def alert_context(event):
    return okta_alert_context(event)
