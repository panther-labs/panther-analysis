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
    # This is the user taking the action.
    actor_username = deep_get(event, "actor", "user", "name", default="<unknown-actor>")
    actor_email = deep_get(event, "actor", "user", "email", default="<unknown-email>")
    # This is the user the action is taken on.
    entity_username = deep_get(event, "entity", "user", "name", default="<unknown-actor>")
    entity_email = deep_get(event, "entity", "user", "email", default="<unknown-email>")
    action = event.get("action")
    if action == "owner_transferred":
        return f"{USER_PRIV_ESC_ACTIONS[action]} from {actor_username} ({actor_email})"

    if action == "permissions_assigned":
        return f"{USER_PRIV_ESC_ACTIONS[action]} {entity_username} ({entity_email})"

    if action == "role_change_to_admin":
        return f"{USER_PRIV_ESC_ACTIONS[action]} {entity_username} ({entity_email})"

    if action == "role_change_to_owner":
        return f"{USER_PRIV_ESC_ACTIONS[action]} {entity_username} ({entity_email})"

    return f"Slack User Privilege Escalation event {action} on {entity_username} ({entity_email})"


def severity(event):
    # Downgrade severity for users assigned permissions
    if event.get("action") == "permissions_assigned":
        return "Medium"
    return "Critical"


def alert_context(event):
    return slack_alert_context(event)
