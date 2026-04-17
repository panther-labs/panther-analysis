from panther_databricks_helpers import DATA_MOVEMENT_CREDENTIAL_ACTIONS, databricks_alert_context


def rule(event):
    action = event.get("actionName")
    # mount is covered by databricks_mount_point_creation; skip it here
    return action in DATA_MOVEMENT_CREDENTIAL_ACTIONS and action != "mount"


def title(event):
    actor = event.deep_get("userIdentity", "email", default="Unknown Actor")
    action = event.get("actionName", "unknown")
    workspace = event.get("workspaceId", "Unknown Workspace")
    return f"Data movement credential operation: {action} in workspace {workspace} by {actor}"


def dedup(event):
    actor = event.deep_get("userIdentity", "email", default="unknown")
    action = event.get("actionName", "unknown")
    return f"data_movement_cred_{actor}_{action}"


def alert_context(event):
    return databricks_alert_context(
        event,
        additional_fields={
            "request_params": event.get("requestParams"),
        },
    )
