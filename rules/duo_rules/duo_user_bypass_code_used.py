from panther_base_helpers import deep_get


def rule(event):
    return event.get("reason") == "bypass_user" and event.get("result") == "success"


def title(event):
    user = deep_get(event, "user", "name", default="Unknown")
    return f"Bypass code for Duo User [{user}] used"


def alert_context(event):
    return {
        "factor": event.get("factor"),
        "reason": event.get("reason"),
        "user": deep_get(event, "user", "name", default=""),
        "os": deep_get(event, "access_device", "os", default=""),
        "ip_access": deep_get(event, "access_device", "ip", default=""),
        "ip_auth": deep_get(event, "auth_device", "ip", default=""),
        "application": deep_get(event, "application", "name", default=""),
    }
