def asana_alert_context(event) -> dict:
    a_c = {
        "actor": "<NO_ACTOR>",
        "context": "<NO_CONTEXT>",
        "event_type": "<NO_EVENT_TYPE>",
        "resource_type": "<NO_RESOURCE_TYPE>",
        "resource_name": "<NO_RESOURCE_NAME>",
        "resource_gid": "<NO_RESOURCE_GID>",
    }
    if event.deep_get("actor", "actor_type", default="") == "user":
        a_c["actor"] = event.deep_get("actor", "email", default="<NO_ACTOR_EMAIL>")
    else:
        a_c["actor"] = event.deep_get("actor", "actor_type", default="<NO_ACTOR>")
    if "event_type" in event:
        # Events have categories and event_type
        # We have not seen category overlap -> only including event_type
        a_c["event_type"] = event.get("event_type")
    a_c["resource_name"] = event.deep_get("resource", "name", default="<NO_RESOURCE_NAME>")
    a_c["resource_gid"] = event.deep_get("resource", "gid", default="<NO_RESOURCE_GID>")
    r_t = event.deep_get("resource", "resource_type")
    if r_t:
        a_c["resource_type"] = r_t
    r_s_t = event.deep_get("resource", "resource_subtype")
    if r_t and r_s_t and r_s_t != r_t:
        a_c["resource_type"] += "__" + r_s_t
    ctx = event.deep_get("context", "context_type")
    if ctx:
        a_c["context"] = ctx
    return a_c
