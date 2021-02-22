from panther_base_helpers import deep_get


def rule(event):
    # Only check password update changes
    if event.get("eventName") != "PasswordUpdated":
        return False

    # Only check root activity
    if deep_get(event, "userIdentity", "type") != "Root":
        return False

    # Only alert if the login was a success
    return deep_get(event, "responseElements", "PasswordUpdated") == "Success"
