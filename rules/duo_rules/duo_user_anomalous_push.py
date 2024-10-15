def rule(event):
    return event.get("reason") == "anomalous_push" and event.get("result") == "denied"


def title(event):
    user = event.deep_get("user", "name", default="Unknown")
    return f"Duo Auth denied due to an anomalous 2FA push for [{user}]"


def alert_context(event):
    return {
        "factor": event.get("factor"),
        "reason": event.get("reason"),
        "user": event.deep_get("user", "name", default=""),
        "os": event.deep_get("access_device", "os", default=""),
        "ip_access": event.deep_get("access_device", "ip", default=""),
        "ip_auth": event.deep_get("auth_device", "ip", default=""),
        "application": event.deep_get("application", "name", default=""),
    }
