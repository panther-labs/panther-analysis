from panther_slack_helpers import slack_alert_context


def rule(event):
    return event.get("action") == "private_channel_converted_to_public"


def alert_context(event):
    return slack_alert_context(event)


def title(event):
    channel_name = event.deep_get("entity", "channel", "name", default="<unknown_channel>")
    name = event.deep_get("actor", "user", "name", default="<unknown_user>")
    email = event.deep_get("actor", "user", "email", default="<unknown_email>")
    return f"Slack private channel {channel_name} made public by {name} <{email}>"
