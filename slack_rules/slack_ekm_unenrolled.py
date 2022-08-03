from panther_base_helpers import slack_alert_context


def rule(event):
    # Only alert on the `ekm_unenrolled` action
    return event.get("action") == "ekm_unenrolled"


def alert_context(event):
    return slack_alert_context(event)
