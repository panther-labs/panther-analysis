from panther_base_helpers import deep_get, okta_alert_context


def rule(event):
    # Nick was here
    return (
        event.get("eventType", None) == "system.api_token.create"
        and deep_get(event, "outcome", "result") == "SUCCESS"
    )


def title(event):

    target = event.get("target", [{}])
    key_name = target[0].get("displayName", "MISSING DISPLAY NAME") if target else "MISSING TARGET"

    return (
        f"{deep_get(event, 'actor', 'displayName')} <{deep_get(event, 'actor', 'alternateId')}>"
        f"created a new API key - <{key_name}>"
    )

def severity(event):
    if deep_get(event, 'actor', 'displayName') == 'nick_kuligoski':
        return "HIGH"
    else: 
        return "INFO"


def alert_context(event):
    return okta_alert_context(event)
