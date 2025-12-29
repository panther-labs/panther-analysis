from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    extract_resource_name_from_id,
)

BLOB_PERMISSIONS_OPERATIONS = [
    "MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/WRITE",
]


def rule(event):
    return event.get(
        "operationName", ""
    ).upper() in BLOB_PERMISSIONS_OPERATIONS and azure_activity_success(event)


def title(event):
    resource_id = event.get("resourceId", "<UNKNOWN_RESOURCE>")

    container_name = extract_resource_name_from_id(
        resource_id, "containers", default="<UNKNOWN_CONTAINER>"
    )
    storage_account_name = extract_resource_name_from_id(
        resource_id, "storageAccounts", default="<UNKNOWN_STORAGE_ACCOUNT>"
    )

    caller = event.get("callerIpAddress", "<UNKNOWN_CALLER>")
    return (
        f"Azure Storage Blob Container Modified: [{container_name}] "
        f"in [{storage_account_name}] by [{caller}]"
    )


def alert_context(event):
    context = azure_activity_alert_context(event)

    resource_id = event.get("resourceId", "")

    container_name = extract_resource_name_from_id(resource_id, "containers", default="")
    if container_name:
        context["container_name"] = container_name

    storage_account_name = extract_resource_name_from_id(resource_id, "storageAccounts", default="")
    if storage_account_name:
        context["storage_account_name"] = storage_account_name

    return context
