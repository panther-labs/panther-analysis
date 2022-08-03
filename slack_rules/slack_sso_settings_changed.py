from panther_base_helpers import slack_alert_context


def rule(event):
    return event.get("action") == "pref.sso_setting_changed"


def alert_context(event):
    # TODO: Add details to context
    return slack_alert_context(event)
