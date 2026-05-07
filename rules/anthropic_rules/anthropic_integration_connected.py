from panther_anthropic_helpers import anthropic_actor_id, anthropic_alert_context


def rule(event):
    return event.get("type") == "integration_user_connected"


def title(event):
    actor_email = anthropic_actor_id(event)
    integration_type = event.get("integration_type", "<UNKNOWN_TYPE>")
    return f"Anthropic: User [{actor_email}] connected [{integration_type}] integration"


def dedup(event):
    return anthropic_actor_id(event)


def alert_context(event):
    return anthropic_alert_context(event)
