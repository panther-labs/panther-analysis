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
    event_type = event.get("type", "")
    email = event.deep_get("actor", "session", "user", "email", default="<UNKNOWN_USER>")

    action_map = {
        "ip_allowlist.created": "Created",
        "ip_allowlist.updated": "Updated",
        "ip_allowlist.deleted": "Deleted",
        "ip_allowlist.config.activated": "Activated",
        "ip_allowlist.config.deactivated": "Deactivated",
    }

    action = action_map.get(event_type, "Modified")
    return f"OpenAI IP Allowlist {action} by [{email}]"


def severity(event):
    event_type = event.get("type")

    if event_type in ["ip_allowlist.deleted", "ip_allowlist.config.deactivated"]:
        return "CRITICAL"

    if event_type == "ip_allowlist.updated":
        return "HIGH"

    if event_type in ["ip_allowlist.created", "ip_allowlist.config.activated"]:
        return "LOW"

    return "DEFAULT"


def alert_context(event):
    event_type = event.get("type")

    context = {
        "event_type": event_type if event_type else "<UNKNOWN_EVENT_TYPE>",
        "event_id": event.get("id", "<UNKNOWN_EVENT_ID>"),
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

    # Add event-specific fields
    if event_type == "ip_allowlist.created":
        context["allowlist_id"] = event.deep_get(
            "ip_allowlist_created", "id", default="<UNKNOWN_ALLOWLIST_ID>"
        )
        context["allowlist_name"] = event.deep_get(
            "ip_allowlist_created", "name", default="<UNKNOWN_ALLOWLIST_NAME>"
        )
        context["allowed_ips"] = event.deep_get("ip_allowlist_created", "allowed_ips", default=[])
    elif event_type == "ip_allowlist.updated":
        context["allowlist_id"] = event.deep_get(
            "ip_allowlist_updated", "id", default="<UNKNOWN_ALLOWLIST_ID>"
        )
        context["allowed_ips"] = event.deep_get("ip_allowlist_updated", "allowed_ips", default=[])
    elif event_type == "ip_allowlist.deleted":
        context["allowlist_id"] = event.deep_get(
            "ip_allowlist_deleted", "id", default="<UNKNOWN_ALLOWLIST_ID>"
        )
        context["allowlist_name"] = event.deep_get(
            "ip_allowlist_deleted", "name", default="<UNKNOWN_ALLOWLIST_NAME>"
        )
        context["allowed_ips"] = event.deep_get("ip_allowlist_deleted", "allowed_ips", default=[])
    elif event_type == "ip_allowlist.config.activated":
        context["activated_configs"] = event.deep_get(
            "ip_allowlist_config_activated", "configs", default=[]
        )
    elif event_type == "ip_allowlist.config.deactivated":
        context["deactivated_configs"] = event.deep_get(
            "ip_allowlist_config_deactivated", "configs", default=[]
        )

    return context
