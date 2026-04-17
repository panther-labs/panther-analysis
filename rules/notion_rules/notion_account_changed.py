from panther_notion_helpers import notion_alert_context


def rule(event):

    allowed_event_types = {
        "user.settings.login_method.email_updated",
        "user.settings.login_method.password_updated",
        "user.settings.login_method.password_added",
        "user.settings.login_method.password_removed",
    }
    if event.deep_walk("event", "type") in allowed_event_types:
        return True
    return False


def title(event):
    user_email = event.deep_walk("event", "actor", "person", "email", default="UNKNOWN EMAIL")
    action_taken = {
        "user.settings.login_method.email_updated": "changed their email",
        "user.settings.login_method.password_updated": "changed their password",
        "user.settings.login_method.password_added": "added a password to their account",
        "user.settings.login_method.password_removed": "removed the password from their account",
    }.get(event.deep_get("event", "type"), "altered their account info")
    return f"Notion User [{user_email}] {action_taken}."


def alert_context(event):
    context = notion_alert_context(event)
    context["login_timestamp"] = event.get("p_event_time")
    context["actor_id"] = event.deep_walk("event", "actor", "id")
    return context
