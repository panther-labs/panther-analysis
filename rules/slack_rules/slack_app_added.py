from panther_base_helpers import deep_get, slack_alert_context

APP_ADDED_ACTIONS = [
    "app_approved",
    "app_installed",
    "org_app_workspace_added",
]


def rule(event):
    return event.get("action") in APP_ADDED_ACTIONS


def title(event):
    return (
        f"Slack App [{deep_get(event, 'entity', 'app', 'name')}] "
        f"Added by [{deep_get(event, 'actor', 'user', 'name')}]"
    )


def alert_context(event):
    context = slack_alert_context(event)
    context["scopes"] = deep_get(event, "entity", "scopes")

    return context


def severity(event):
    # Used to escalate to High/Critical if the app is granted admin privileges
    # May want to escalate to "Critical" depending on security posture
    if "admin" in deep_get(event, "entity", "app", "scopes", default=[]):
        return "High"

    # Fallback method in case the admin scope is not directly mentioned in entity for whatever
    if "admin" in deep_get(event, "details", "new_scope", default=[]):
        return "High"

    if "admin" in deep_get(event, "details", "bot_scopes", default=[]):
        return "High"

    return "Medium"
