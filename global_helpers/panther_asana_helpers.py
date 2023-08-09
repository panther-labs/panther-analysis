from panther_base_helpers import deep_get


def asana_alert_context(event: dict) -> dict:
    a_c = {
        "actor": "<NO_ACTOR>",
        "context": "<NO_CONTEXT>",
        "event_type": "<NO_EVENT_TYPE>",
        "resource_type": "<NO_RESOURCE_TYPE>",
        "resource_name": "<NO_RESOURCE_NAME>",
        "resource_gid": "<NO_RESOURCE_GID>",
    }
    if deep_get(event, "actor", "actor_type", default="") == "user":
        a_c["actor"] = deep_get(event, "actor", "email", default="<NO_ACTOR_EMAIL>")
    else:
        a_c["actor"] = deep_get(event, "actor", "actor_type", default="<NO_ACTOR>")
    if "event_type" in event:
        # Events have categories and event_type
        # We have not seen category overlap -> only including event_type
        a_c["event_type"] = event.get("event_type")
    a_c["resource_name"] = deep_get(event, "resource", "name", default="<NO_RESOURCE_NAME>")
    a_c["resource_gid"] = deep_get(event, "resource", "gid", default="<NO_RESOURCE_GID>")
    r_t = deep_get(event, "resource", "resource_type")
    if r_t:
        a_c["resource_type"] = r_t
    r_s_t = deep_get(event, "resource", "resource_subtype")
    if r_t and r_s_t and r_s_t != r_t:
        a_c["resource_type"] += "__" + r_s_t
    ctx = deep_get(event, "context", "context_type")
    if ctx:
        a_c["context"] = ctx
    return a_c
