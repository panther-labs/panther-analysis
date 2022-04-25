from panther_base_helpers import deep_get, okta_alert_context

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
        deep_get(event, "actor", "alternateId") == "system@okta.com"
        and deep_get(event, "transaction", "id") == "unknown"
        and deep_get(event, "userAgent", "rawUserAgent") is None
        and deep_get(event, "client", "geographicalContext", "country") is None
    )


def title(event):
    return f"Okta Support Reset Password or MFA for user {event.udm('actor_user')}"


def alert_context(event):
    return okta_alert_context(event)
