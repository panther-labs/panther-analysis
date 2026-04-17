from panther_databricks_helpers import SYSTEM_USERS, databricks_alert_context

# Destructive action prefixes/names to match
DESTRUCTIVE_PREFIXES = ["delete", "drop", "trash", "destroy", "purge"]


def rule(event):
    action = event.get("actionName", "").lower()

    # Exclude system users
    user = event.deep_get("userIdentity", "email", default="")
    if user in SYSTEM_USERS:
        return False

    # Exclude non-destructive actions that contain "delete" as substring
    if action.startswith("undelete") or action.startswith("restore"):
        return False

    # Check for destructive action prefixes
    return any(action.startswith(prefix) for prefix in DESTRUCTIVE_PREFIXES)


def dedup(event):
    user = event.deep_get("userIdentity", "email", default="unknown")
    return f"destructive_{user}"


def title(event):
    user = event.deep_get("userIdentity", "email", default="Unknown User")
    action = event.get("actionName", "delete")
    return f"High volume destructive activities by {user} (>50/day, action: {action})"


def alert_context(event):
    return databricks_alert_context(event)
