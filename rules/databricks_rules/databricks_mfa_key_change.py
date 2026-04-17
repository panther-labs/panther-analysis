from panther_databricks_helpers import MFA_ACTIONS, databricks_alert_context


def rule(event):
    if event.get("serviceName") != "accounts":
        return False

    action = event.get("actionName")
    return action in MFA_ACTIONS["add"] or action in MFA_ACTIONS["delete"]


def title(event):
    action = event.get("actionName", "unknown")
    actor = event.deep_get("userIdentity", "email", default="Unknown Actor")
    change_type = "added" if action in MFA_ACTIONS["add"] else "deleted"
    return f"MFA key {change_type} by {actor}"


def dedup(event):
    actor = event.deep_get("userIdentity", "email", default="unknown")
    action = event.get("actionName", "unknown")
    return f"mfa_key_change_{actor}_{action}"


def alert_context(event):
    return databricks_alert_context(
        event,
        additional_fields={
            "change_type": "add" if event.get("actionName") in MFA_ACTIONS["add"] else "delete",
        },
    )
