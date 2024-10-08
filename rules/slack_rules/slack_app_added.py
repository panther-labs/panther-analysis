from panther_slack_helpers import slack_alert_context

APP_ADDED_ACTIONS = [
    "app_approved",
    "app_installed",
    "org_app_workspace_added",
]


def rule(event):
    return event.get("action") in APP_ADDED_ACTIONS


def title(event):
    return (
        f"Slack App [{event.deep_get('entity', 'app', 'name')}] "
        f"Added by [{event.deep_get('actor', 'user', 'name')}]"
    )


def alert_context(event):
    context = slack_alert_context(event)
    context["scopes"] = event.deep_get("entity", "scopes")

    return context


def severity(event):
    # Used to escalate to High/Critical if the app is granted admin privileges
    # May want to escalate to "Critical" depending on security posture
    if "admin" in event.deep_get("entity", "app", "scopes", default=[]):
        return "High"

    # Fallback method in case the admin scope is not directly mentioned in entity for whatever
    if "admin" in event.deep_get("details", "new_scope", default=[]):
        return "High"

    if "admin" in event.deep_get("details", "bot_scopes", default=[]):
        return "High"

    return "Medium"
