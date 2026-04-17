def tailscale_alert_context(event) -> dict:
    a_c = {}
    a_c["actor"] = event.deep_get("event", "actor", default="<NO_ACTOR_FOUND>")
    a_c["action"] = event.deep_get("event", "action", default="<NO_ACTION_FOUND>")
    return a_c


def is_tailscale_admin_console_event(event):
    origin = event.deep_get("event", "origin", default="")
    return origin == "ADMIN_CONSOLE"
