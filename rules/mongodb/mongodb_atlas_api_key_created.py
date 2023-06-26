def rule(event):
    return event.get("eventTypeName", "") == "API_KEY_ACCESS_LIST_ENTRY_ADDED"


def title(event):
    user = event.get("username", "<USER_NOT_FOUND>")
    public_key = event.get("targetPublicKey", "<PUBLIC_KEY_NOT_FOUND>")
    return f"MongoDB Atlas: [{user}] updated the allowed access list for API Key [{public_key}]"


def alert_context(event):
    return {
        "links": event.get("links", [{}])[0].get("href", "<LINKS_NOT_FOUND>"),
        "username": event.get("username", "<USER_NOT_FOUND>"),
        "event_type_name": event.get("eventTypeName", "<EVENT_TYPE_NOT_FOUND>"),
        "org_id": event.get("orgId", "<ORG_ID_NOT_FOUND>"),
        "target_public_key": event.get("targetPublicKey", "<PUBLIC_KEY_NOT_FOUND>"),
    }
