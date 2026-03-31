from panther_databricks_helpers import SYSTEM_USERS, databricks_alert_context


def rule(event):
    # Filter out system users and unknown
    user = event.deep_get("userIdentity", "email", default="")
    if user in SYSTEM_USERS or user in ("", "unknown"):
        return False

    # Must have workspace context
    return event.get("workspaceId") is not None


def dedup(event):
    user = event.deep_get("userIdentity", "email", default="unknown")
    return user


def unique(event):
    workspace = event.get("workspaceId", "unknown")
    return workspace


def title(event):
    user = event.deep_get("userIdentity", "email", default="Unknown User")
    return f"User accessing multiple workspaces: {user} (≥5 workspaces/day)"


def alert_context(event):
    return databricks_alert_context(event)
