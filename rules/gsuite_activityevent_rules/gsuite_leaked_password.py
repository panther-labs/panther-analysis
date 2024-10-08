PASSWORD_LEAKED_EVENTS = {
    "account_disabled_password_leak",
}


def rule(event):
    if event.deep_get("id", "applicationName") != "login":
        return False

    if event.get("type") == "account_warning":
        return bool(event.get("name") in PASSWORD_LEAKED_EVENTS)
    return False


def title(event):
    user = event.deep_get("parameters", "affected_email_address")
    if not user:
        user = "<UNKNOWN_USER>"
    return f"User [{user}]'s account was disabled due to a password leak"
