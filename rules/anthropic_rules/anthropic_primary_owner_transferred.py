from panther_anthropic_helpers import anthropic_actor_id, anthropic_alert_context


def rule(event):
    return event.get("type") == "primary_owner_transferred"


def title(event):
    actor_email = anthropic_actor_id(event)
    return f"Anthropic: Primary owner transferred by [{actor_email}]"


def dedup(event):
    return anthropic_actor_id(event)


def alert_context(event):
    return anthropic_alert_context(event)
