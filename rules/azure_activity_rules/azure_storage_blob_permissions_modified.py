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

    return (
        f"Azure Storage Blob Container Modified: [{container_name}] " f"in [{storage_account_name}]"
    )


def alert_context(event):
    context = azure_activity_alert_context(event)
    return context
