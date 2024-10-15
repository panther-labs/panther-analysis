def notion_alert_context(event) -> dict:
    a_c = {}
    a_c["actor"] = event.deep_get("event", "actor", default="<NO_ACTOR_FOUND>")
    a_c["action"] = event.deep_get("event", "type", default="<NO_ACTION_FOUND>")
    return a_c
