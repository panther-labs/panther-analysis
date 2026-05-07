from panther_anthropic_helpers import anthropic_alert_context


def rule(event):
    return event.get("type") == "claude_organization_settings_updated"


def title(event):
    actor_email = event.deep_get("actor", "email_address", default="<UNKNOWN_EMAIL_ADDRESS>")
    updates = event.get("updates", [])
    if updates and isinstance(updates, list):
        update_types = ", ".join(u.get("type", "unknown") for u in updates if isinstance(u, dict))
        return f"Anthropic: Organization settings updated by [{actor_email}]: {update_types}"
    return f"Anthropic: Organization settings updated by [{actor_email}]"


def dedup(event):
    return event.deep_get("actor", "email_address", default="<UNKNOWN_EMAIL_ADDRESS>")


def alert_context(event):
    return anthropic_alert_context(event)
