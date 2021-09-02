from panther_base_helpers import deep_get

# Remove any unapproved login methods
APPROVED_LOGIN_TYPES = {
    "exchange",
    "google_password",
    "reauth",
    "saml",
    "unknown",
}


def rule(event):
    if event.get("type") != "login":
        return False

    if (
        event.get("type") == "login"
        and event.get("name") != "logout"
        and deep_get(event, "parameters", "login_type")
        not in APPROVED_LOGIN_TYPES
    ):
        return True

    return False


def title(event):
    return (
        f"A login attempt of a non-approved type was detected for user "
        f"[{deep_get(event, 'actor', 'email', default='<UNKNOWN_USER>')}]"
    )
