from panther_anthropic_helpers import anthropic_alert_context


def rule(event):
    return event.get("type") == "claude_chat_access_failed"


def title(event):
    actor_email = event.deep_get("actor", "email_address", default="<UNKNOWN_EMAIL_ADDRESS>")
    return f"Anthropic: Excessive chat access failures from [{actor_email}]"


def dedup(event):
    return (
        event.deep_get("actor", "email_address")
        or event.deep_get("actor", "api_key_id")
        or event.deep_get("actor", "ip_address", default="<UNKNOWN_ACTOR>")
    )


def alert_context(event):
    return anthropic_alert_context(event)
