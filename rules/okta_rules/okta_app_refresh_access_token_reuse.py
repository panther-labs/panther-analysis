from panther_base_helpers import okta_alert_context


def rule(event):
    return event.get("eventtype") in (
        "app.oauth2.as.token.detect_reuse",
        "app.oauth2.token.detect_reuse",
    )


def title(event):
    return (
        "Okta Access Token Reuse Attempted by "
        f"[{event.get('client', {}).get('ipAddress')}] "
        f"[{event.get('actor', {}).get('displayName', '<no-displayname-found>')}]"
    )


def alert_context(event):
    return okta_alert_context(event)
