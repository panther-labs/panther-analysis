from panther_base_helpers import deep_get, slack_alert_context

APP_REMOVED_ACTIONS = [
    "app_restricted",
    "app_uninstalled",
    "org_app_workspace_removed",
]


def rule(event):
    return event.get("action") in APP_REMOVED_ACTIONS


def title(event):
    return f"Slack App [{deep_get(event, 'entity', 'app', 'name')}] " \
           f"Removed by [{deep_get(event, 'actor', 'user', 'name')}]"


def alert_context(event):
    return slack_alert_context(event)
