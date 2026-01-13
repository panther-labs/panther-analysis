ELEVATED_SCOPES = {"all", "models:write", "organization:write", "api_keys:write", "admin"}


def rule(event):
    if event.get("type") not in ["api_key.created", "api_key.updated"]:
        return False

    field = "api_key_created" if event.get("type") == "api_key.created" else "api_key_updated"
    scopes = event.deep_get(field, "data", "scopes", default=[])

    return any(scope.lower() in {s.lower() for s in ELEVATED_SCOPES} for scope in scopes if scope)


def title(event):
    event_type = event.get("type", "")
    email = event.deep_get("actor", "session", "user", "email", default="<UNKNOWN_USER>")
    return f"OpenAI API Key with Elevated Scopes: {event_type} by [{email}]"


def severity(event):
    field = "api_key_created" if event.get("type") == "api_key.created" else "api_key_updated"
    scopes = event.deep_get(field, "data", "scopes", default=[])

    if not scopes:
        return "DEFAULT"

    if any(s.lower() in ["all", "admin"] for s in scopes):
        return "HIGH"
    if any(s.lower() in {s.lower() for s in ELEVATED_SCOPES} for s in scopes):
        return "MEDIUM"

    return "DEFAULT"


def alert_context(event):
    field = "api_key_created" if event.get("type") == "api_key.created" else "api_key_updated"
    return {
        "event_type": event.get("type", "<UNKNOWN_EVENT_TYPE>"),
        "event_id": event.get("id", "<UNKNOWN_EVENT_ID>"),
        "api_key_id": event.deep_get(field, "id", default="<UNKNOWN_API_KEY_ID>"),
        "api_key_scopes": event.deep_get(field, "data", "scopes", default=[]),
        "actor_email": event.deep_get(
            "actor", "session", "user", "email", default="<UNKNOWN_ACTOR_EMAIL>"
        ),
        "actor_id": event.deep_get("actor", "session", "user", "id", default="<UNKNOWN_ACTOR_ID>"),
        "source_ip": event.deep_get(
            "actor", "session", "ip_address", default="<UNKNOWN_SOURCE_IP>"
        ),
        "user_agent": event.deep_get(
            "actor", "session", "user_agent", default="<UNKNOWN_USER_AGENT>"
        ),
    }
