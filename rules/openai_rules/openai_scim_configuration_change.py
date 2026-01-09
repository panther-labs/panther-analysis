from panther_base_helpers import deep_get


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
        "event_type": event.get("type"),
        "event_id": event.get("id"),
        "scim_resource_id": deep_get(event, field, "id"),
        "actor_email": deep_get(event, "actor", "session", "user", "email"),
        "actor_id": deep_get(event, "actor", "session", "user", "id"),
        "source_ip": deep_get(event, "actor", "session", "ip_address"),
        "user_agent": deep_get(event, "actor", "session", "user_agent"),
        "ip_details": deep_get(event, "actor", "session", "ip_address_details"),
    }
