from panther_base_helpers import deep_get, slack_alert_context

USER_PRIV_ESC_ACTIONS = {
    "owner_transferred": "Slack Owner Transferred",
    "permissions_assigned": "Slack User Assigned Permissions",
    "role_change_to_admin": "Slack User Made Admin",
    "role_change_to_owner": "Slack User Made Owner",
}


def rule(event):
    return event.get("action") in USER_PRIV_ESC_ACTIONS


def title(event):
    username = deep_get(event, "actor", "user", "name", default="<unknown-actor>")
    email = deep_get(event, "actor", "user", "email", default="<unknown-email>")

    if event.get("action") == "owner_transferred":
        return f"Slack Owner Transferred from {username} ({email})"

    if event.get("action") == "permissions_assigned":
        return f"Slack User, {username} ({email}), assigned permissions"

    if event.get("action") == "role_change_to_admin":
        return f"{username} ({email}) promoted to admin"

    if event.get("action") == "role_change_to_owner":
        return f"{username} ({email}) promoted to Owner"

    return "Slack User Privilege Escalation"


def severity(event):
    # Downgrade severity for users assigned permissions
    if event.get("action") == "permissions_assigned":
        return "Medium"
    if event.get("action") == "role_change_to_admin" or "role_change_to_owner":
        return "Critical"
    return "High"


def alert_context(event):
    return slack_alert_context(event)
