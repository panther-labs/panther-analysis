def auth0_alert_context(event) -> dict:
    a_c = {}
    a_c["actor"] = event.deep_get(
        "data", "details", "request", "auth", "user", default="<NO_ACTOR_FOUND>"
    )
    a_c["action"] = event.deep_get("data", "description", default="<NO_ACTION_FOUND>")
    return a_c


def is_auth0_config_event(event):
    channel = event.deep_get("data", "details", "request", "channel", default="")
    return channel == "https://manage.auth0.com/"
