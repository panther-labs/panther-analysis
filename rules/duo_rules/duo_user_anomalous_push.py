from panther_base_helpers import deep_get


def rule(event):
    return event.get("reason") == "anomalous_push" and event.get("result") == "denied"


def title(event):
    # pylint: disable=line-too-long
    return f"Duo Auth denied due to an anomalous 2FA push for {deep_get(event, 'user', 'name', default='<Unknown>')}"


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
