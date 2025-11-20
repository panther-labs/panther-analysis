from panther_notion_helpers import notion_alert_context


def rule(event):

    if event.deep_walk("event", "type") == "user.login":
        return True
    return False


def title(event):
    user_email = event.deep_walk("event", "actor", "person", "email", default="UNKNOWN EMAIL")
    return f"Notion User [{user_email}] logged in."


def alert_context(event):
    context = notion_alert_context(event)
    context["login_timestamp"] = event.get("p_event_time")
    context["actor_id"] = event.deep_walk("event", "actor", "id")
    return context
