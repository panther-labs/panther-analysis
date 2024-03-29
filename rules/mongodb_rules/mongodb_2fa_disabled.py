def rule(event):
    return event.deep_get("eventTypeName", default="") == "ORG_TWO_FACTOR_AUTH_OPTIONAL"


def title(event):
    user = event.deep_get("username", default="<USER_NOT_FOUND>")
    return f"MongoDB Atlas: [{user}] has disabled 2FA"


def alert_context(event):
    links = event.deep_walk("links", "href", return_val="first", default="<LINKS_NOT_FOUND>")
    return {
        "links": links,
        "username": event.deep_get("username", default="<USER_NOT_FOUND>"),
        "event_type_name": event.deep_get("eventTypeName", default="<EVENT_TYPE_NOT_FOUND>"),
        "org_id": event.deep_get("orgId", default="<ORG_ID_NOT_FOUND>"),
        "target_public_key": event.deep_get("targetPublicKey", default="<PUBLIC_KEY_NOT_FOUND>"),
    }
