def rule(event):
    """Detect API token update events in Panther."""
    return event.get("actionName") == "UPDATE_API_TOKEN"


def title(event):
    """Return a title for the alert."""
    return (
        f"API Token Updated - Token [{event.deep_get('actor', 'name')}] "
        f"by [{event.udm('actor_user') or event.deep_get('actor', 'name')}]"
    )


def alert_context(event):
    """Return context for the alert."""
    return {
        "token_name": event.deep_get("actor", "name"),
        "token_id": event.deep_get("actor", "id"),
        "user": event.udm("actor_user"),
        "source_ip": event.get("sourceIP"),
        "timestamp": event.get("timestamp"),
        "action_params": event.get("actionParams"),
    }


def dedup(event):
    """Deduplicate by token id (or name if id is missing)."""
    return event.deep_get("actor", "id") or event.deep_get("actor", "name")
