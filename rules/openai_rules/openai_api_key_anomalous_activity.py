from panther_base_helpers import deep_get

ELEVATED_SCOPES = {
    "all",
    "models:write",
    "organization:write",
    "api_keys:write",
    "admin",
}


def get_api_key_scopes(event):
    event_type = event.get("type", "")
    if event_type not in ["api_key.created", "api_key.updated"]:
        return []

    field_name = "api_key_created" if event_type == "api_key.created" else "api_key_updated"
    return deep_get(event, field_name, "data", "scopes", default=[])


def has_elevated_scopes(scopes):
    if not scopes:
        return False

    elevated_lower = {s.lower() for s in ELEVATED_SCOPES}
    return any(e in str(scope).lower() for scope in scopes for e in elevated_lower)


def get_actor_email(event):
    actor = event.get("actor", {})
    actor_type = actor.get("type", "")

    if actor_type == "session":
        return deep_get(actor, "session", "user", "email", default="Unknown User")
    if actor_type == "api_key":
        email = deep_get(actor, "api_key", "user", "email", default="")
        return email if email else "Unknown User"

    return "Unknown User"


def get_actor_identifier(event):
    actor = event.get("actor", {})
    actor_type = actor.get("type", "")

    if actor_type == "session":
        return deep_get(actor, "session", "user", "id", default="unknown")
    if actor_type == "api_key":
        return deep_get(actor, "api_key", "id", default="unknown")

    return event.get("id", "unknown")


def rule(event):
    scopes = get_api_key_scopes(event)
    return has_elevated_scopes(scopes)


def title(event):
    event_type = event.get("type", "Unknown")
    actor = event.get("actor", {})
    actor_type = actor.get("type", "")

    if actor_type == "session":
        email = get_actor_email(event)
        return f"Anomalous OpenAI API Key Activity: {event_type} by {email}"

    if actor_type == "api_key":
        service_id = deep_get(actor, "api_key", "service_account", "id", default="")
        email = deep_get(actor, "api_key", "user", "email", default="")

        if service_id:
            return (
                f"Anomalous OpenAI API Key Activity: {event_type} "
                f"by service account {service_id}"
            )
        if email:
            return f"Anomalous OpenAI API Key Activity: {event_type} " f"by {email} (API Key)"

    return f"Anomalous OpenAI API Key Activity: {event_type}"


def dedup(event):
    event_type = event.get("type", "")
    user_id = get_actor_identifier(event)
    return f"{event_type}:{user_id}"


def severity(event):
    scopes = get_api_key_scopes(event)
    return "HIGH" if has_elevated_scopes(scopes) else "DEFAULT"


def alert_context(event):
    context = {
        "event_type": event.get("type"),
        "event_id": event.get("id"),
        "effective_at": event.get("effective_at"),
    }

    actor = event.get("actor", {})
    actor_type = actor.get("type", "")

    if actor_type == "session":
        context.update(
            {
                "actor_type": "user_session",
                "user_email": deep_get(actor, "session", "user", "email"),
                "user_id": deep_get(actor, "session", "user", "id"),
                "source_ip": deep_get(actor, "session", "ip_address"),
                "user_agent": deep_get(actor, "session", "user_agent"),
                "ja3_fingerprint": deep_get(actor, "session", "ja3"),
                "ja4_fingerprint": deep_get(actor, "session", "ja4"),
            }
        )

        ip_details = deep_get(actor, "session", "ip_address_details", default={})
        if ip_details:
            context.update(
                {
                    "country": ip_details.get("country"),
                    "city": ip_details.get("city"),
                    "asn": ip_details.get("asn"),
                }
            )

    elif actor_type == "api_key":
        context.update(
            {
                "actor_type": "api_key",
                "api_key_type": deep_get(actor, "api_key", "type"),
                "api_key_id": deep_get(actor, "api_key", "id"),
            }
        )

        if deep_get(actor, "api_key", "user"):
            context.update(
                {
                    "user_email": deep_get(actor, "api_key", "user", "email"),
                    "user_id": deep_get(actor, "api_key", "user", "id"),
                }
            )
        elif deep_get(actor, "api_key", "service_account"):
            context["service_account_id"] = deep_get(actor, "api_key", "service_account", "id")

    event_type = event.get("type", "")
    event_field_map = {
        "api_key.created": "api_key_created",
        "api_key.updated": "api_key_updated",
        "api_key.deleted": "api_key_deleted",
    }

    if event_type in event_field_map:
        field_name = event_field_map[event_type]
        context["api_key_id"] = deep_get(event, field_name, "id")
        if event_type != "api_key.deleted":
            context["api_key_data"] = deep_get(event, field_name, "data")

    return context
