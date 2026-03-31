from panther_databricks_helpers import databricks_alert_context


def rule(event):
    if event.get("serviceName") != "accounts":
        return False

    return event.get("actionName") == "removePrincipalFromGroup"


def title(event):
    target_user = event.deep_get("requestParams", "targetUserName", default="Unknown User")
    target_group = event.deep_get("requestParams", "targetGroupName", default="Unknown Group")
    actor = event.deep_get("userIdentity", "email", default="Unknown Actor")
    return f"Principal {target_user} removed from group {target_group} by {actor}"


def dedup(event):
    target_user = event.deep_get("requestParams", "targetUserName", default="unknown")
    target_group = event.deep_get("requestParams", "targetGroupName", default="unknown")
    return f"principal_removed_{target_group}_{target_user}"


def alert_context(event):
    return databricks_alert_context(
        event,
        additional_fields={
            "target_user": event.deep_get("requestParams", "targetUserName"),
            "target_group": event.deep_get("requestParams", "targetGroupName"),
        },
    )
