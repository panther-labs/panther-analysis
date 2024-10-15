from panther_base_helpers import okta_alert_context


def rule(event):
    return (
        event.get("eventType", None) == "system.api_token.create"
        and event.deep_get("outcome", "result") == "SUCCESS"
    )


def title(event):
    target = event.get("target", [{}])
    key_name = target[0].get("displayName", "MISSING DISPLAY NAME") if target else "MISSING TARGET"

    return (
        f"{event.deep_get('actor', 'displayName')} <{event.deep_get('actor', 'alternateId')}>"
        f"created a new API key - <{key_name}>"
    )


def alert_context(event):
    return okta_alert_context(event)
