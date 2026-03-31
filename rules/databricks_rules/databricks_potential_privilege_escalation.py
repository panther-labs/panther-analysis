from panther_databricks_helpers import PRIVILEGE_MODIFICATION_ACTIONS, databricks_alert_context


def rule(event):
    return event.get("actionName") in PRIVILEGE_MODIFICATION_ACTIONS


def dedup(event):
    user = event.deep_get("userIdentity", "email", default="unknown")
    return f"priv_escalation_{user}"


def title(event):
    user = event.deep_get("userIdentity", "email", default="Unknown User")
    return f"Potential privilege escalation by {user} (>25 permission changes/hour)"


def alert_context(event):
    return databricks_alert_context(event)
