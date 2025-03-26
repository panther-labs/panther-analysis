# allow-list of approved login types
# comment or uncomment approved login types as needed
APPROVED_LOGIN_TYPES = {
    "exchange",
    "google_password",
    "reauth",
    "saml",
    # "unknown",
}

# allow-list any application names here
APPROVED_APPLICATION_NAMES = {"saml"}


def rule(event):
    if event.get("type") != "login":
        return False

    if event.get("name") == "logout":
        return False

    if (
        event.deep_get("parameters", "login_type") in APPROVED_LOGIN_TYPES
        or event.deep_get("id", "applicationName") in APPROVED_APPLICATION_NAMES
    ):
        return False

    return True


def title(event):
    return (
        f"A login attempt of a non-approved type was detected for user "
        f"[{event.deep_get('actor', 'email', default='<UNKNOWN_USER>')}]"
    )
