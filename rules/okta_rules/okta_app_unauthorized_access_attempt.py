from panther_base_helpers import deep_get, okta_alert_context


def rule(event):
    return event.get("eventtype", "") == "app.generic.unauth_app_access_attempt"


def title(event):
    return (
        f"[{deep_get(event, 'actor', 'alternateId', default = 'id-not-found')}] "
        f"attempted unauthorized access to "
        f"[{event.get('target', [{}])[0].get('alternateId','id-not-found')}]"
    )


def alert_context(event):
    return okta_alert_context(event)
