from panther_base_helpers import slack_alert_context


def rule(event):
    return event.get("action") == "intune_disabled"


def alert_context(event):
    return slack_alert_context(event)
