from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    extract_resource_name_from_id,
)

RESOURCE_GROUP_DELETE = "MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/DELETE"


def rule(event):
    return event.get(
        "operationName", ""
    ).upper() == RESOURCE_GROUP_DELETE and azure_activity_success(event)


def title(event):
    resource_id = event.get("resourceId", "")
    resource_group = extract_resource_name_from_id(
        resource_id, "resourceGroups", default="<UNKNOWN_RESOURCE_GROUP>"
    )

    return f"Azure Resource Group [{resource_group}] deleted"


def alert_context(event):
    context = azure_activity_alert_context(event)

    resource_id = event.get("resourceId", "")

    resource_group_name = extract_resource_name_from_id(resource_id, "resourceGroups", default="")
    if resource_group_name:
        context["resource_group_name"] = resource_group_name

    return context
