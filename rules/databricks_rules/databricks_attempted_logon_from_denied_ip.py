from panther_databricks_helpers import databricks_alert_context, filter_noise


def rule(event):
    if event.get("serviceName") != "accounts":
        return False

    if event.get("actionName") != "IpAccessDenied":
        return False

    # Filter out system noise using helper
    if filter_noise(event):
        return False

    return True


def title(event):
    user = event.deep_get("userIdentity", "email", default="Unknown User")
    source_ip = event.get("sourceIPAddress", "Unknown IP")
    workspace = event.get("workspaceId", "Unknown Workspace")
    return (
        f"Blocked login attempt from denied IP {source_ip} for user {user} to workspace {workspace}"
    )


def dedup(event):
    source_ip = event.get("sourceIPAddress", "unknown")
    workspace = event.get("workspaceId", "unknown")
    return f"denied_ip_login_{workspace}_{source_ip}"


def alert_context(event):
    return databricks_alert_context(
        event, additional_fields={"path": event.deep_get("requestParams", "path")}
    )
