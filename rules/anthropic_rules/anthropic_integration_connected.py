from panther_anthropic_helpers import anthropic_alert_context


def rule(event):
    return event.get("type") == "integration_user_connected"


def title(event):
    actor_email = event.deep_get("actor", "email_address", default="<UNKNOWN_EMAIL_ADDRESS>")
    integration_type = event.get("integration_type", "<UNKNOWN_TYPE>")
    return f"Anthropic: User [{actor_email}] connected [{integration_type}] integration"


def dedup(event):
    return event.deep_get("actor", "email_address", default="<UNKNOWN_EMAIL_ADDRESS>")


def alert_context(event):
    return anthropic_alert_context(event)
