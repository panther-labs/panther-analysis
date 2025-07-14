SUSPICIOUS_LOGIN_TYPES = {
    "suspicious_login",
    "suspicious_login_less_secure_app",
    "suspicious_programmatic_login",
}


def rule(event):
    if event.deep_get("id", "applicationName") != "login":
        return False

    if event.get("name") in SUSPICIOUS_LOGIN_TYPES:
        return True

    return False


def title(event):
    user = event.deep_get("actor", "email", default="<UNKNOWN_USER>")
    return f"A suspicious login was reported for user [{user}]"
