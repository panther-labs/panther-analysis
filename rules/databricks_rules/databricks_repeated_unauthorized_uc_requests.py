from panther_databricks_helpers import databricks_alert_context


def rule(event):
    # Must be Unity Catalog service
    if event.get("serviceName") != "unityCatalog":
        return False

    # Check for unauthorized status codes
    status_code = event.deep_get("response", "statusCode")
    return status_code in [401, 403]


def dedup(event):
    user = event.deep_get("userIdentity", "email", default="unknown")
    return f"uc_unauthorized_{user}"


def title(event):
    user = event.deep_get("userIdentity", "email", default="Unknown User")
    action = event.get("actionName", "Unknown Action")
    return f"Repeated unauthorized Unity Catalog requests by {user} ({action})"


def alert_context(event):
    return databricks_alert_context(
        event,
        additional_fields={"uc_action": event.get("actionName")},
    )
