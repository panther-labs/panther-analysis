from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    extract_resource_name_from_id,
)

RESTORE_POINT_DELETE_OPERATION = "MICROSOFT.COMPUTE/RESTOREPOINTCOLLECTIONS/DELETE"


def rule(event):
    return event.get(
        "operationName", ""
    ).upper() == RESTORE_POINT_DELETE_OPERATION and azure_activity_success(event)


def title(event):
    resource_id = event.get("resourceId", "<UNKNOWN_RESOURCE>")

    collection_name = extract_resource_name_from_id(
        resource_id, "restorePointCollections", default="<UNKNOWN_COLLECTION>"
    )

    return f"Azure Restore Point Collection Deleted: [{collection_name}]"


def alert_context(event):
    context = azure_activity_alert_context(event)

    resource_id = event.get("resourceId", "")

    resource_group = extract_resource_name_from_id(resource_id, "resourceGroups", default="")
    if resource_group:
        context["resource_group"] = resource_group

    return context
