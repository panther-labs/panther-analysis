from panther_base_helpers import deep_get

ELEVATED_SCOPES = {"all", "models:write", "organization:write", "api_keys:write", "admin"}


def rule(event):
    if event.get("type") not in ["api_key.created", "api_key.updated"]:
        return False

    field = "api_key_created" if event.get("type") == "api_key.created" else "api_key_updated"
    scopes = deep_get(event, field, "data", "scopes", default=[])

    return any(scope.lower() in {s.lower() for s in ELEVATED_SCOPES} for scope in scopes if scope)


def title(event):
    event_type = event.get("type", "")
    email = event.deep_get("actor", "session", "user", "email", default="<UNKNOWN_USER>")
    return f"OpenAI API Key with Elevated Scopes: {event_type} by [{email}]"


def severity(event):
    field = "api_key_created" if event.get("type") == "api_key.created" else "api_key_updated"
    scopes = deep_get(event, field, "data", "scopes", default=[])

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
        "event_type": event.get("type"),
        "event_id": event.get("id"),
        "api_key_id": deep_get(event, field, "id"),
        "api_key_scopes": deep_get(event, field, "data", "scopes", default=[]),
        "actor_email": deep_get(event, "actor", "session", "user", "email"),
        "actor_id": deep_get(event, "actor", "session", "user", "id"),
        "source_ip": deep_get(event, "actor", "session", "ip_address"),
        "user_agent": deep_get(event, "actor", "session", "user_agent"),
    }
