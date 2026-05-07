import re

from panther_anthropic_helpers import anthropic_actor_id, anthropic_alert_context

PARENT_EVENT_TYPE = "claude_organization_settings_updated"


def rule(event):
    return event.get("type") == PARENT_EVENT_TYPE


def _extract_update_types(updates):
    """Extract update type values from the updates list.

    Uses string parsing because Panther's event wrapper intercepts
    .get("type") on nested objects, returning the parent event's type.
    """
    matches = re.findall(r"'type':\s*'([^']+)'", str(updates))
    if not matches:
        matches = re.findall(r'"type":\s*"([^"]+)"', str(updates))
    return [m for m in matches if m != PARENT_EVENT_TYPE]


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
