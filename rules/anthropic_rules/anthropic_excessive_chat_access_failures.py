from panther_anthropic_helpers import anthropic_actor_id, anthropic_alert_context


def rule(event):
    return event.get("type") == "claude_chat_access_failed"


def title(event):
    return f"Anthropic: Excessive chat access failures from [{anthropic_actor_id(event)}]"


def dedup(event):
    return anthropic_actor_id(event)


def alert_context(event):
    return anthropic_alert_context(event)
