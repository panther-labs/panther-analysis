from panther_anthropic_helpers import anthropic_actor_id, anthropic_alert_context


def rule(event):
    event_type = event.get("type")
    if event_type == "org_sso_toggled":
        return event.get("is_enabled") in (False, "false")
    if event_type == "org_sso_connection_deactivated":
        return True
    return False


def title(event):
    actor_email = anthropic_actor_id(event)
    event_type = event.get("type")
    if event_type == "org_sso_toggled":
        return f"Anthropic: SSO disabled by [{actor_email}]"
    return f"Anthropic: SSO connection deactivated by [{actor_email}]"


def dedup(event):
    return anthropic_actor_id(event)


def alert_context(event):
    return anthropic_alert_context(event)
