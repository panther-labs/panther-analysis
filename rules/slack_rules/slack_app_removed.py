from panther_slack_helpers import slack_alert_context

APP_REMOVED_ACTIONS = [
    "app_restricted",
    "app_uninstalled",
    "org_app_workspace_removed",
]


def rule(event):
    return event.get("action") in APP_REMOVED_ACTIONS


def title(event):
    return (
        f"Slack App [{event.deep_get('entity', 'app', 'name')}] "
        f"Removed by [{event.deep_get('actor', 'user', 'name')}]"
    )


def alert_context(event):
    return slack_alert_context(event)
