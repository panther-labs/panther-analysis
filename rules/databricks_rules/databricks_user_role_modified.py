from panther_databricks_helpers import databricks_alert_context


def rule(event):
    if event.get("serviceName") != "accounts":
        return False

    return event.get("actionName") in ["addUserToAdminGroup", "modifyUserRole"]


def title(event):
    action = event.get("actionName", "Unknown Action")
    actor = event.deep_get("userIdentity", "email", default="Unknown User")
    return f"User role modified: {action} by {actor}"


def alert_context(event):
    return databricks_alert_context(
        event, additional_fields={"request_params": event.get("requestParams")}
    )
