from panther_base_helpers import deep_get, okta_alert_context


def rule(event):
    return (
        event.get("eventType", None) == "system.api_token.revoke"
        and deep_get(event, "outcome", "result") == "SUCCESS"
    )


def title(event):
    target = event.get("target", [{}])
    key_name = target[0].get("displayName", "MISSING DISPLAY NAME") if target else "MISSING TARGET"

    return (
        f"{deep_get(event, 'actor', 'displayName')} <{deep_get(event, 'actor', 'alternateId')}>"
        f"revoked API key - <{key_name}>"

    )


def alert_context(event):
    return okta_alert_context(event)
