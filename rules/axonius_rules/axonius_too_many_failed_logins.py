import time

from panther_detection_helpers.caching import (
    get_counter,
    increment_counter,
    reset_counter,
    set_key_expiration,
)

MAX_FAILS = 5
TIME_WINDOW = 60 * 5
CACHE_PREFIX = "axonius_too_many_failed_logins:"


def rule(event):
    action = event.deep_get("event", "action", default="")
    status = event.deep_get("event", "params", "status", default="")
    username = event.deep_get("event", "user", default="")
    if status != "successful" and action == "AuditAction.LoginFrom":
        cache_key = f"{CACHE_PREFIX}{username}"
        count = int(get_counter(cache_key))
        if count > MAX_FAILS:
            reset_counter(cache_key)
            return True

        increment_counter(cache_key)
        set_key_expiration(cache_key, time.time() + TIME_WINDOW)
    return False


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
