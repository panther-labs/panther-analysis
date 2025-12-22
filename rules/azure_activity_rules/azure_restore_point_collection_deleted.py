from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

RESTORE_POINT_DELETE_OPERATION = "MICROSOFT.COMPUTE/RESTOREPOINTCOLLECTIONS/DELETE"


def rule(event):
    return event.get(
        "operationName", ""
    ).upper() == RESTORE_POINT_DELETE_OPERATION and azure_activity_success(event)


def title(event):
    resource_id = event.get("resourceId", "<UNKNOWN_RESOURCE>")

    collection_name = "<UNKNOWN_COLLECTION>"
    if resource_id:
        parts = resource_id.split("/")
        if "restorePointCollections" in parts:
            try:
                collection_name = parts[parts.index("restorePointCollections") + 1]
            except (IndexError, ValueError):
                pass

    caller = event.get("callerIpAddress", "<UNKNOWN_CALLER>")
    return f"Azure Restore Point Collection Deleted: [{collection_name}] by [{caller}]"


def alert_context(event):
    context = azure_activity_alert_context(event)

    resource_id = event.get("resourceId", "")
    if resource_id:
        parts = resource_id.split("/")
        if "restorePointCollections" in parts:
            try:
                context["restore_point_collection_name"] = parts[
                    parts.index("restorePointCollections") + 1
                ]
            except (IndexError, ValueError):
                pass

    return context
