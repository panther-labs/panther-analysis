from panther_databricks_helpers import databricks_alert_context


def rule(event):
    if event.get("serviceName") != "accounts":
        return False

    return event.get("actionName") == "changePassword"


def title(event):
    actor = event.deep_get("userIdentity", "email", default="Unknown Actor")
    status_code = event.deep_get("response", "statusCode")
    status = "Success" if status_code == 200 else "Failed"
    return f"Password changed by {actor} - {status}"


def dedup(event):
    actor = event.deep_get("userIdentity", "email", default="unknown")
    return f"password_changed_{actor}"


def alert_context(event):
    return databricks_alert_context(event)
