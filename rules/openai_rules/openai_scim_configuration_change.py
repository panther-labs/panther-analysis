def rule(event):
    return event.get("type") in ["scim.enabled", "scim.disabled"]


def title(event):
    event_type = event.get("type", "")
    action = "Enabled" if event_type == "scim.enabled" else "Disabled"
    email = event.deep_get("actor", "session", "user", "email", default="<UNKNOWN_USER>")
    return f"OpenAI SCIM {action} by [{email}]"


def severity(event):
    if event.get("type") == "scim.disabled":
        return "HIGH"
    if event.get("type") == "scim.enabled":
        return "LOW"
    return "DEFAULT"


def alert_context(event):
    field = "scim_enabled" if event.get("type") == "scim.enabled" else "scim_disabled"
    return {
        "event_type": event.get("type", "<UNKNOWN_EVENT_TYPE>"),
        "event_id": event.get("id", "<UNKNOWN_EVENT_ID>"),
        "scim_resource_id": event.deep_get(field, "id", default="<UNKNOWN_SCIM_RESOURCE_ID>"),
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
        "ip_details": event.deep_get("actor", "session", "ip_address_details", default={}),
    }
