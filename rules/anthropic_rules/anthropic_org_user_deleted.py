from panther_anthropic_helpers import anthropic_alert_context


def rule(event):
    return event.get("type") == "org_user_deleted"


def title(event):
    actor_email = event.deep_get("actor", "email_address", default="<UNKNOWN_EMAIL_ADDRESS>")
    deleted_user = event.get("deleted_user_email") or event.get("deleted_user_id", "<UNKNOWN_USER>")
    return f"Anthropic: User [{deleted_user}] deleted from org by [{actor_email}]"


def dedup(event):
    return event.deep_get("actor", "email_address", default="<UNKNOWN_EMAIL_ADDRESS>")


def alert_context(event):
    return anthropic_alert_context(event)
