import re

from panther_anthropic_helpers import anthropic_actor_id, anthropic_alert_context

PARENT_EVENT_TYPE = "claude_organization_settings_updated"


def rule(event):
    return event.get("type") == PARENT_EVENT_TYPE


def _extract_update_type(entry_str):
    """Extract the first type value from a single serialized update entry."""
    match = re.search(r"'type':\s*'([^']+)'", entry_str)
    if not match:
        match = re.search(r'"type":\s*"([^"]+)"', entry_str)
    return match.group(1) if match else None


def _extract_update_types(updates):
    """Extract top-level update type values from the updates list.

    Serializes each entry individually to avoid capturing type values
    from nested objects. Uses string parsing because Panther's event
    wrapper intercepts .get("type") on nested objects.
    """
    result = []
    for entry in updates:
        update_type = _extract_update_type(str(entry))
        if update_type and update_type != PARENT_EVENT_TYPE:
            result.append(update_type)
    return result


def title(event):
    actor_email = anthropic_actor_id(event)
    updates = event.get("updates", [])
    if updates:
        update_types = _extract_update_types(updates)
        if update_types:
            types_str = ", ".join(update_types)
            return f"Anthropic: Organization settings updated by" f" [{actor_email}]: {types_str}"
    return f"Anthropic: Organization settings updated by [{actor_email}]"


def dedup(event):
    return anthropic_actor_id(event)


def alert_context(event):
    return anthropic_alert_context(event)
