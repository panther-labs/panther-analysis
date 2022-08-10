from panther_base_helpers import slack_alert_context


def rule(event):
    return event.get("action") == "anomaly"


def alert_context(event):
    # TODO: Add more details to context
    return slack_alert_context(event)
