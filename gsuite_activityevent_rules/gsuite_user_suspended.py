from panther_base_helpers import deep_get

USER_SUSPENDED_EVENTS = {
    "account_disabled_generic",
    "account_disabled_spamming_through_relay",
    "account_disabled_spamming",
    "account_disabled_hijacked",
}


def rule(event):
    if deep_get(event, "id", "applicationName") != "login":
        return False

    return bool(event.get("name") in USER_SUSPENDED_EVENTS)


def title(event):
    user = deep_get(event, "parameters", "affected_email_address")
    if not user:
        user = "<UNKNOWN_USER>"
    return f"User [{user}]'s account was disabled"
