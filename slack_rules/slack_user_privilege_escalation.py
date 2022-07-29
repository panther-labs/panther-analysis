from panther_base_helpers import slack_alert_context

USER_PRIV_ESC_ACTIONS = {
    "owner_transferred": "Slack Owner Transferred",
    "permissions_assigned": "Slack User Assigned Permissions",
    "role_change_to_admin": "Slack User Made Admin",
    "role_change_to_owner": "Slack User Made Owner",
}


def rule(event):
    return event.get("action") in USER_PRIV_ESC_ACTIONS


def title(event):
    if event.get("action") in USER_PRIV_ESC_ACTIONS:
        return USER_PRIV_ESC_ACTIONS.get(event.get("action"))
    return "Slack User Privilege Escalation"


def severity(event):
    # Downgrade severity for users assigned permissions
    # TODO: Add case to check for admin privileges
    if event.get("action") == "permissions_assigned":
        return "Medium"
    return "Critical"


def alert_context(event):
    return slack_alert_context(event)
