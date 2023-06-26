from panther_base_helpers import deep_get, deep_walk


def rule(event):
    return deep_get(event, "eventTypeName", default="") == "API_KEY_ACCESS_LIST_ENTRY_ADDED"


def title(event):
    user = deep_get(event, "username", default="<USER_NOT_FOUND>")
    public_key = deep_get(event, "targetPublicKey", default="<PUBLIC_KEY_NOT_FOUND>")
    return f"MongoDB Atlas: [{user}] updated the allowed access list for API Key [{public_key}]"


def alert_context(event):
    links = deep_walk(event, "links", "href", return_val="first", default="<LINKS_NOT_FOUND>")
    return {
        "links": links,
        "username": deep_get(event, "username", default="<USER_NOT_FOUND>"),
        "event_type_name": deep_get(event, "eventTypeName", default="<EVENT_TYPE_NOT_FOUND>"),
        "org_id": deep_get(event, "orgId", default="<ORG_ID_NOT_FOUND>"),
        "target_public_key": deep_get(event, "targetPublicKey", default="<PUBLIC_KEY_NOT_FOUND>"),
    }
