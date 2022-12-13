from panther_base_helpers import deep_get


def rule(event):
    return event.get("result") == "fraud"


def title(event):
    return f"A DUO action was marked as fraudulent by {deep_get(event, 'user', 'name')}"


def alert_context(event):
    return {
        "factor": event.get("factor"),
        "reason": event.get("reason"),
        "user": deep_get(event, "user", "name"),
        "os": deep_get(event, "access_device", "os"),
        "ip_access": deep_get(event, "access_device", "ip"),
        "ip_auth": deep_get(event, "auth_device", "ip"),
        "application": deep_get(event, "application", "name"),
    }
