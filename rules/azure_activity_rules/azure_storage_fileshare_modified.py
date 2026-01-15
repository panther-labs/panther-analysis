from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    extract_resource_name_from_id,
)

FILESHARE_OPERATIONS = [
    "MICROSOFT.STORAGE/STORAGEACCOUNTS/FILESERVICES/SHARES/WRITE",
]


def rule(event):
    return event.get(
        "operationName", ""
    ).upper() in FILESHARE_OPERATIONS and azure_activity_success(event)


def title(event):
    resource_id = event.get("resourceId", "<UNKNOWN_RESOURCE>")
    share_name = extract_resource_name_from_id(resource_id, "shares", default="<UNKNOWN_SHARE>")
    return f"Azure Storage File Share Created or Modified: [{share_name}]"


def alert_context(event):
    context = azure_activity_alert_context(event)

    resource_id = event.get("resourceId", "")

    share_name = extract_resource_name_from_id(resource_id, "shares", default="")
    if share_name:
        context["share_name"] = share_name
    return context
