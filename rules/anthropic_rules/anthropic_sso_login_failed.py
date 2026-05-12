from panther_anthropic_helpers import anthropic_actor_id, anthropic_alert_context


def rule(event):
    return event.get("type") == "sso_login_failed"


def title(event):
    actor = anthropic_actor_id(event)
    return f"Anthropic: SSO login failed from [{actor}]"


def dedup(event):
    return anthropic_actor_id(event)


def alert_context(event):
    return anthropic_alert_context(event)
