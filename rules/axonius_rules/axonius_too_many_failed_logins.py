def rule(event):
    action = event.deep_get("event", "action", default="")
    status = event.deep_get("event", "params", "status", default="")
    username = event.deep_get("event", "user", default="")
    return status != "successful" and action == "AuditAction.LoginFrom" and bool(username)


def dedup(event):
    return event.deep_get("event", "user", default="<UNKNOWN_USER>")


def title(event):
    username = event.deep_get("event", "user", default="")
    return f"[Axonius] Too many failed Login from {username}"


def alert_context(event):
    username = event.deep_get("event", "user", default="")
    ip_address = event.deep_get("event", "params", "ip", default="")
    action = event.deep_get("event", "action", default="")
    status = event.deep_get("event", "params", "status", default="")

    context = {
        "username": username,
        "ip_address": ip_address,
        "action": action,
        "status": status,
    }
    return context
