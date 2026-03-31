from panther_databricks_helpers import (
    databricks_alert_context,
    get_config_key_value,
    is_config_change,
)


def rule(event):
    # Must be workspace-level audit event
    if event.get("auditLevel") != "WORKSPACE_LEVEL":
        return False

    # Check if it's a workspace configuration change
    return is_config_change(event, config_category="workspace")


def title(event):
    action = event.get("actionName", "Unknown Action")
    actor = event.deep_get("userIdentity", "email", default="Unknown Actor")
    workspace = event.get("workspaceId", "Unknown Workspace")
    status_code = event.deep_get("response", "statusCode")
    status = "Success" if status_code == 200 else "Failed"

    # Include the config key in the title when available
    config_key, _ = get_config_key_value(event)
    if config_key:
        return f"Workspace config change ({config_key}) in {workspace} by {actor} - {status}"

    return f"Workspace configuration change ({action}) in {workspace} by {actor} - {status}"


def dedup(event):
    workspace = event.get("workspaceId", "unknown")
    config_key, _ = get_config_key_value(event)
    return f"workspace_config_change_{workspace}_{config_key}"


def alert_context(event):
    config_key, config_value = get_config_key_value(event)
    return databricks_alert_context(
        event,
        additional_fields={
            "change_scope": "WORKSPACE_LEVEL",
            "config_key": config_key,
            "config_value": config_value,
        },
    )
