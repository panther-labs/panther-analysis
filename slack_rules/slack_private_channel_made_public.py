from panther_base_helpers import slack_alert_context


def rule(event):
    return event.get("action") == "private_channel_converted_to_public"


def alert_context(event):
    return slack_alert_context(event)
