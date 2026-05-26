from panther_okta_helpers import okta_alert_context


SERVICE_APP_ACTOR_TYPE = "PublicClientAppEntity"


def rule(event):
    if event.get("eventType") != "user.mfa.factor.deactivate":
        return False
    return event.deep_get("actor", "type", default="") == SERVICE_APP_ACTOR_TYPE


def title(event):
    app = event.deep_get("actor", "displayName", default="<unknown app>")
    target = event.get("target") or [{}]
    victim = target[0].get("alternateId", "<unknown user>")
    return f"Okta service app [{app}] deactivated MFA factor for [{victim}]"


def alert_context(event):
    return okta_alert_context(event)
