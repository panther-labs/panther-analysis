def rule(event):
    return event.get("eventtypename", "") == "API_KEY_ACCESS_LIST_ENTRY_ADDED"


def title(event):
    user = event.get("username", "<USER_NOT_FOUND>")
    public_key = event.get("targetpublickey", "<PUBLIC_KEY_NOT_FOUND>")
    return f"MongoDB Atlas: [{user}] created a new API Key [{public_key}]"


def alert_context(event):
    return {
        "links": event.get("links", [{}])[0].get("href", "<LINKS_NOT_FOUND>"),
        "username": event.get("username", "<USER_NOT_FOUND>"),
        "eventtypename": event.get("eventtypename", "<EVENT_TYPE_NOT_FOUND>"),
        "orgid": event.get("orgid", "<ORG_ID_NOT_FOUND>"),
        "targetpublickey": event.get("targetpublickey", "<PUBLIC_KEY_NOT_FOUND>"),
    }
