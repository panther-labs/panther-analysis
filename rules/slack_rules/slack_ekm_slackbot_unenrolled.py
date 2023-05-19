from panther_base_helpers import slack_alert_context


def rule(event):
    # Only alert on the `ekm_slackbot_unenroll_notification_sent` action
    return event.get("action") == "ekm_slackbot_unenroll_notification_sent"


def alert_context(event):
    return slack_alert_context(event)
