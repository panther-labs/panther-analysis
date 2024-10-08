from panther_slack_helpers import slack_alert_context


def rule(event):
    return event.get("action") == "pref.two_factor_auth_changed"


def alert_context(event):
    # TODO: Add details to context
    return slack_alert_context(event)
