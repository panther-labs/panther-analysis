from panther_anthropic_helpers import anthropic_alert_context


def rule(event):
    return event.get("type") == "role_assignment_granted"


def title(event):
    actor_email = event.deep_get("actor", "email_address", default="<UNKNOWN_EMAIL_ADDRESS>")
    role = event.get("role", "<UNKNOWN_ROLE>")
    target_id = event.get("target_id", "<UNKNOWN_TARGET>")
    return f"Anthropic: Role [{role}] granted to [{target_id}] by [{actor_email}]"


def dedup(event):
    return event.deep_get("actor", "email_address", default="<UNKNOWN_EMAIL_ADDRESS>")


def alert_context(event):
    return anthropic_alert_context(event)
