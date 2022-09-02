from panther_base_helpers import slack_alert_context


def rule(event):
    return event.get("action") == "organization_deleted"


def alert_context(event):
    return slack_alert_context(event)
