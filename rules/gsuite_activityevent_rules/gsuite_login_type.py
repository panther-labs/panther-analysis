from panther_base_helpers import deep_get

# allow-list of approved login types
APPROVED_LOGIN_TYPES = {
    "exchange",
    "google_password",
    "reauth",
    "saml",
    "unknown",
}

# allow-list any application names here
APPROVED_APPLICATION_NAMES = {"saml"}


def rule(event):
    if event.get("type") != "login":
        return False

    if event.get("name") == "logout":
        return False

    if (
        deep_get(event, "parameters", "login_type") in APPROVED_LOGIN_TYPES
        or deep_get(event, "id", "applicationName") in APPROVED_APPLICATION_NAMES
    ):
        return False

    return True


def title(event):
    return (
        f"A login attempt of a non-approved type was detected for user "
        f"[{deep_get(event, 'actor', 'email', default='<UNKNOWN_USER>')}]"
    )
