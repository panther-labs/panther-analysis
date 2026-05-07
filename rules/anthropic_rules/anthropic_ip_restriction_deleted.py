from panther_anthropic_helpers import anthropic_alert_context


def rule(event):
    return event.get("type") == "org_ip_restriction_deleted"


def title(event):
    actor_email = event.deep_get("actor", "email_address", default="<UNKNOWN_EMAIL_ADDRESS>")
    return f"Anthropic: IP restriction deleted by [{actor_email}]"


def dedup(event):
    return event.deep_get("actor", "email_address", default="<UNKNOWN_EMAIL_ADDRESS>")


def alert_context(event):
    return anthropic_alert_context(event)
