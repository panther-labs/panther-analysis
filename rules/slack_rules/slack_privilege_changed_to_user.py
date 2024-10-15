from panther_base_helpers import slack_alert_context


def rule(event):
    return event.get("action") == "role_change_to_user"


def title(event):
    username = event.deep_get("entity", "user", "name", default="<unknown-entity>")
    email = event.deep_get("entity", "user", "email", default="<unknown-email>")

    return f"Slack {username}'s ({email}) role changed to User"


def alert_context(event):
    return slack_alert_context(event)
