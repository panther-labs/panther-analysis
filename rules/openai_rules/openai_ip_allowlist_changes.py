from panther_base_helpers import deep_get

IP_ALLOWLIST_EVENTS = [
    "ip_allowlist.created",
    "ip_allowlist.updated",
    "ip_allowlist.deleted",
    "ip_allowlist.config.activated",
    "ip_allowlist.config.deactivated",
]


def rule(event):
    return event.get("type") in IP_ALLOWLIST_EVENTS


def title(event):
    event_type = event.get("type", "Unknown")
    email = deep_get(event, "actor", "session", "user", "email", default="Unknown User")

    action_map = {
        "ip_allowlist.created": "Created",
        "ip_allowlist.updated": "Updated",
        "ip_allowlist.deleted": "Deleted",
        "ip_allowlist.config.activated": "Activated",
        "ip_allowlist.config.deactivated": "Deactivated",
    }

    action = action_map.get(event_type, "Modified")
    return f"OpenAI IP Allowlist {action} by {email}"


def severity(event):
    event_type = event.get("type")

    if event_type in ["ip_allowlist.deleted", "ip_allowlist.config.deactivated"]:
        return "CRITICAL"

    if event_type == "ip_allowlist.updated":
        return "HIGH"

    if event_type in ["ip_allowlist.created", "ip_allowlist.config.activated"]:
        return "MEDIUM"

    return "DEFAULT"


def alert_context(event):
    event_type = event.get("type")

    context = {
        "event_type": event_type,
        "event_id": event.get("id"),
        "actor_email": deep_get(event, "actor", "session", "user", "email"),
        "actor_id": deep_get(event, "actor", "session", "user", "id"),
        "source_ip": deep_get(event, "actor", "session", "ip_address"),
        "user_agent": deep_get(event, "actor", "session", "user_agent"),
        "ip_details": deep_get(event, "actor", "session", "ip_address_details"),
    }

    # Add event-specific fields
    if event_type == "ip_allowlist.created":
        context["allowlist_id"] = deep_get(event, "ip_allowlist_created", "id")
        context["allowlist_name"] = deep_get(event, "ip_allowlist_created", "name")
        context["allowed_ips"] = deep_get(event, "ip_allowlist_created", "allowed_ips")
    elif event_type == "ip_allowlist.updated":
        context["allowlist_id"] = deep_get(event, "ip_allowlist_updated", "id")
        context["allowed_ips"] = deep_get(event, "ip_allowlist_updated", "allowed_ips")
    elif event_type == "ip_allowlist.deleted":
        context["allowlist_id"] = deep_get(event, "ip_allowlist_deleted", "id")
        context["allowlist_name"] = deep_get(event, "ip_allowlist_deleted", "name")
        context["allowed_ips"] = deep_get(event, "ip_allowlist_deleted", "allowed_ips")
    elif event_type == "ip_allowlist.config.activated":
        context["activated_configs"] = deep_get(event, "ip_allowlist_config_activated", "configs")
    elif event_type == "ip_allowlist.config.deactivated":
        context["deactivated_configs"] = deep_get(
            event, "ip_allowlist_config_deactivated", "configs"
        )

    return context
