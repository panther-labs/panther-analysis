from panther_databricks_helpers import databricks_alert_context


def rule(event):
    return event.get("actionName") == "mount"


def title(event):
    actor = event.deep_get("userIdentity", "email", default="Unknown Actor")
    mount_point = event.deep_get("requestParams", "mountPoint", default="Unknown Mount")
    workspace = event.get("workspaceId", "Unknown Workspace")
    return f"Mount point created: {mount_point} in workspace {workspace} by {actor}"


def dedup(event):
    mount_point = event.deep_get("requestParams", "mountPoint", default="unknown")
    workspace = event.get("workspaceId", "unknown")
    return f"mount_point_{workspace}_{mount_point}"


def alert_context(event):
    return databricks_alert_context(
        event,
        additional_fields={
            "mount_point": event.deep_get("requestParams", "mountPoint"),
            "mount_config": event.get("requestParams"),
        },
    )
