from panther_slack_helpers import slack_alert_context


def rule(event):
    return event.get("action") == "organization_created"


def alert_context(event):
    return slack_alert_context(event)
