from panther_anthropic_helpers import anthropic_actor_id, anthropic_alert_context


def rule(event):
    return event.get("type") == "admin_api_key_created"


def title(event):
    actor_email = anthropic_actor_id(event)
    return f"Anthropic: Admin API key created by [{actor_email}]"


def dedup(event):
    return anthropic_actor_id(event)


def alert_context(event):
    return anthropic_alert_context(event)
