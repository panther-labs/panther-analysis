SUSPICIOUS_LOGIN_TYPES = {
    "suspicious_login",
    "suspicious_login_less_secure_app",
    "suspicious_programmatic_login",
}


def rule(event):
    if event.deep_get("id", "applicationName") != "login":
        return False

    return bool(event.get("name") in SUSPICIOUS_LOGIN_TYPES)


def title(event):
    user = event.deep_get("parameters", "affected_email_address")
    if not user:
        user = "<UNKNOWN_USER>"
    return f"A suspicious login was reported for user [{user}]"
