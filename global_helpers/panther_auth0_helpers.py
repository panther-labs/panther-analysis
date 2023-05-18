from panther_base_helpers import deep_get


def auth0_alert_context(event) -> dict:
    a_c = {}
    a_c["actor"] = deep_get(
        event, "data", "details", "request", "auth", "user", default="<NO_ACTOR_FOUND>"
    )
    a_c["action"] = deep_get(event, "data", "description", default="<NO_ACTION_FOUND>")
    return a_c


def is_auth0_config_event(event):
    channel = deep_get(event, "data", "details", "request", "channel", default="")
    return channel == "https://manage.auth0.com/"
