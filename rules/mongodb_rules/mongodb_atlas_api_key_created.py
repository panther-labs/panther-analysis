from panther_mongodb_helpers import mongodb_alert_context


def rule(event):
    return event.deep_get("eventTypeName", default="") == "API_KEY_ACCESS_LIST_ENTRY_ADDED"


def title(event):
    user = event.deep_get("username", default="<USER_NOT_FOUND>")
    public_key = event.deep_get("targetPublicKey", default="<PUBLIC_KEY_NOT_FOUND>")
    return f"MongoDB Atlas: [{user}] updated the allowed access list for API Key [{public_key}]"


def alert_context(event):
    context = mongodb_alert_context(event)
    links = event.deep_walk("links", "href", return_val="first", default="<LINKS_NOT_FOUND>")
    extra_context = {
        "links": links,
        "event_type_name": event.deep_get("eventTypeName", default="<EVENT_TYPE_NOT_FOUND>"),
        "target_public_key": event.deep_get("targetPublicKey", default="<PUBLIC_KEY_NOT_FOUND>"),
    }
    context.update(extra_context)

    return context
