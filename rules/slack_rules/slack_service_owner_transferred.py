from panther_slack_helpers import slack_alert_context


def rule(event):
    return event.get("action") == "service_owner_transferred"


def alert_context(event):
    return slack_alert_context(event)
