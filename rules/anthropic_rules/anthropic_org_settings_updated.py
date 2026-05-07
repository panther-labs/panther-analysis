from panther_anthropic_helpers import anthropic_actor_id, anthropic_alert_context


def rule(event):
    return event.get("type") == "claude_organization_settings_updated"


def title(event):
    actor_email = anthropic_actor_id(event)
    updates = event.get("updates", [])
    if updates and isinstance(updates, list):
        update_types = ", ".join(u.get("type", "unknown") for u in updates if isinstance(u, dict))
        return f"Anthropic: Organization settings updated by [{actor_email}]: {update_types}"
    return f"Anthropic: Organization settings updated by [{actor_email}]"


def dedup(event):
    return anthropic_actor_id(event)


def alert_context(event):
    return anthropic_alert_context(event)
