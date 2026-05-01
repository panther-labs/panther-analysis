def rule(event):
    return event.get("type") == "login.failed"


def unique(event):
    return event.deep_get("actor", "session", "ip_address", default="UNKNOWN_IP")


def dedup(event):
    return event.deep_get("actor", "session", "user", "email", default="UNKNOWN_EMAIL")


def title(event):
    email = event.deep_get("actor", "session", "user", "email", default="UNKNOWN_EMAIL")
    return f"[OpenAI] Credential stuffing detected against account [{email}]"


def alert_context(event):
    return {
        "email": event.deep_get("actor", "session", "user", "email", default="UNKNOWN_EMAIL"),
        "ip_address": event.deep_get("actor", "session", "ip_address", default="UNKNOWN_IP"),
        "error_code": event.deep_get("login_failed", "error_code", default="UNKNOWN"),
    }
