from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    extract_resource_name_from_id,
)

WORKSPACE_DELETE = "MICROSOFT.OPERATIONALINSIGHTS/WORKSPACES/DELETE"


def rule(event):
    return event.get("operationName", "").upper() == WORKSPACE_DELETE and azure_activity_success(
        event
    )


def title(event):
    resource_id = event.get("resourceId", "")
    workspace = extract_resource_name_from_id(
        resource_id, "workspaces", default="<UNKNOWN_WORKSPACE>"
    )

    return f"Azure Log Analytics Workspace deleted [{workspace}]"


def alert_context(event):
    context = azure_activity_alert_context(event)

    resource_id = event.get("resourceId", "")

    workspace_name = extract_resource_name_from_id(resource_id, "workspaces", default="")
    if workspace_name:
        context["workspace_name"] = workspace_name

    resource_group = extract_resource_name_from_id(resource_id, "resourceGroups", default="")
    if resource_group:
        context["resource_group"] = resource_group

    return context
