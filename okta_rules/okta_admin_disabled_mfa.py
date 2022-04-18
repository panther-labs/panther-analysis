import panther_event_type_helpers as event_type


def rule(event):
    return event.udm("event_type") == event_type.ADMIN_MFA_DISABLED


def title(event):
    return f"Okta System-wide MFA Disabled by Admin User {event.udm('actor_user')}"


def alert_context(event):
    context = {
        "user": event.udm("actor_user"),
        "ip": event.udm("source_ip"),
        "event": event.get("eventType"),
    }
    return context
