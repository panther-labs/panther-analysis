STANDARD_LOGIN_TYPES = {"exchange", "google_password", "reauth", "saml"}


def rule(event):
    if event.deep_get("id", "applicationName") != "login":
        return False
    if event.get("name") != "login_success":
        return False
    # Exclude IPv6 addresses to avoid false positives from dual-stack networking
    ip_address = event.get("ipAddress", "")
    if ":" in ip_address:
        return False
    return bool(ip_address)


def title(event):
    user = event.deep_get("actor", "email", default="<UNKNOWN_USER>")
    return f"Google Workspace: User [{user}] authenticated from multiple distinct IPs in 6 hours"


def dedup(event):
    return event.deep_get("actor", "email", default="")


def unique(event):
    return event.get("ipAddress", "")


def severity(event):
    login_type = event.deep_get("parameters", "login_type", default="")
    if login_type and login_type not in STANDARD_LOGIN_TYPES:
        return "HIGH"
    return "DEFAULT"


def alert_context(event):
    return {
        "user": event.deep_get("actor", "email"),
        "ip_address": event.get("ipAddress"),
        "login_type": event.deep_get("parameters", "login_type"),
    }
