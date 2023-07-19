from panther_base_helpers import deep_get


def tailscale_alert_context(event) -> dict:
    a_c = {}
    a_c["actor"] = deep_get(event, "event", "actor", default="<NO_ACTOR_FOUND>")
    a_c["action"] = deep_get(event, "event", "action", default="<NO_ACTION_FOUND>")
    return a_c


def is_tailscale_admin_console_event(event):
    origin = deep_get(event, "event", "origin", default="")
    return origin == "ADMIN_CONSOLE"
