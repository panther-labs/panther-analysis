SUSPICIOUS_LOGIN_TYPES = {
    "suspicious_login",
    "suspicious_login_less_secure_app",
    "suspicious_programmatic_login",
}


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

    if event.deep_get("parameters", "is_suspicious") is True:
        return True

    return False


def title(event):
    user = event.deep_get("actor", "email")
    if not user:
        user = "<UNKNOWN_USER>"
    return f"A suspicious login was reported for user [{user}]"
