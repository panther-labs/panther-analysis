from panther_gsuite_helpers import gsuite_activityevent_alert_context

USER_SUSPENDED_EVENTS = {
    "account_disabled_generic",
    "account_disabled_spamming_through_relay",
    "account_disabled_spamming",
    "account_disabled_hijacked",
}


def rule(event):
    if event.deep_get("id", "applicationName") != "login":
        return False

    return bool(event.get("name") in USER_SUSPENDED_EVENTS)


def title(event):
    user = event.deep_get("parameters", "affected_email_address")
    if not user:
        user = "<UNKNOWN_USER>"
    return f"User [{user}]'s account was disabled"


def alert_context(event):
    return gsuite_activityevent_alert_context(event)
