from panther_base_helpers import slack_alert_context

INFORMATION_BARRIER_ACTIONS = {
    "barrier_deleted": "Slack Information Barrier Deleted",
    "barrier_updated": "Slack Information Barrier Updated",
}


def rule(event):
    return event.get("action") in INFORMATION_BARRIER_ACTIONS


def title(event):
    if event.get("action") in INFORMATION_BARRIER_ACTIONS:
        return INFORMATION_BARRIER_ACTIONS.get(event.get("action"))
    return "Slack Information Barrier Modified"


def alert_context(event):
    return slack_alert_context(event)
