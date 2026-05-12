from panther_anthropic_helpers import anthropic_actor_id, anthropic_alert_context


def rule(event):
    return event.get("type") == "role_assignment_granted"


def title(event):
    actor_email = anthropic_actor_id(event)
    role = event.get("role", "<UNKNOWN_ROLE>")
    target_id = event.get("target_id", "<UNKNOWN_TARGET>")
    return f"Anthropic: Role [{role}] granted to [{target_id}] by [{actor_email}]"


def dedup(event):
    return anthropic_actor_id(event)


def alert_context(event):
    return anthropic_alert_context(event)
