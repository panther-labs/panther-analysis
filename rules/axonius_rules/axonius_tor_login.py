from panther_tor_helpers import TorExitNodes


def rule(event):
    action = event.deep_get("event", "action", default="")
    status = event.deep_get("event", "params", "status", default="")
    if status == "successful" and action == "AuditAction.LoginFrom":
        return TorExitNodes(event).has_exit_nodes()
    return False


def title(event):
    username = event.deep_get("event", "user", default="")
    return f"[Axonius] Login from {username} Detected on a TOR IP Address"


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
