from panther_okta_helpers import okta_alert_context

OKTA_SUPPORT_RESET_EVENTS = [
    "user.account.reset_password",
    "user.mfa.factor.update",
    "system.mfa.factor.deactivate",
    "user.mfa.attempt_bypass",
]


def rule(event):
    if event.get("eventType") not in OKTA_SUPPORT_RESET_EVENTS:
        return False
    return (
        event.deep_get("actor", "alternateId") == "system@okta.com"
        and event.deep_get("transaction", "id") == "unknown"
        and event.deep_get("userAgent", "rawUserAgent") is None
        and event.deep_get("client", "geographicalContext", "country") is None
    )


def title(event):
    return f"Okta Support Reset Password or MFA for user {event.udm('actor_user')}"


def alert_context(event):
    return okta_alert_context(event)
