from panther_auth0_helpers import auth0_alert_context

SUSPICIOUS_EVENT_TYPES = (
    "fs",
    "ss",
    "signup_pwd_leak",
)


def rule(event):
    return event.deep_get("data", "type") in SUSPICIOUS_EVENT_TYPES


def title(event):
    event_type = event.deep_get("data", "type")
    user = event.deep_get(
        "data", "details", "request", "auth", "user", "email", default="<NO_USER_FOUND>"
    )
    p_source_label = event.get("p_source_label", "<NO_P_SOURCE_LABEL_FOUND>")
    return (
        f"Auth0 User [{user}] had a surge of suspicious [{event_type}] event in "
        f"your organization's tenant [{p_source_label}]."
    )


def alert_context(event):
    return auth0_alert_context(event)
