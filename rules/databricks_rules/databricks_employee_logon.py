from panther_databricks_helpers import (
    databricks_alert_context,
    is_databricks_employee_auth,
    is_login_action,
)


def rule(event):
    if event.get("serviceName") != "accounts":
        return False

    if not is_login_action(event):
        return False

    if not is_databricks_employee_auth(event):
        return False

    # Check for successful response
    status_code = event.deep_get("response", "statusCode")
    if status_code != 200:
        return False

    # Check for workspace-level audit
    if event.get("auditLevel") != "WORKSPACE_LEVEL":
        return False

    return True


def title(event):
    user = event.deep_get("userIdentity", "email", default="Unknown User")
    workspace = event.get("workspaceId", "Unknown Workspace")
    return f"Databricks employee logged into workspace {workspace} as {user}"


def alert_context(event):
    return databricks_alert_context(
        event,
        additional_fields={"auth_method": event.deep_get("requestParams", "authentication_method")},
    )
