from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

BLOB_PERMISSIONS_OPERATIONS = [
    "MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/WRITE",
]


def rule(event):
    return event.get(
        "operationName", ""
    ).upper() in BLOB_PERMISSIONS_OPERATIONS and azure_activity_success(event)


def title(event):
    resource_id = event.get("resourceId", "<UNKNOWN_RESOURCE>")

    container_name = "<UNKNOWN_CONTAINER>"
    storage_account_name = "<UNKNOWN_STORAGE_ACCOUNT>"

    if resource_id:
        parts = resource_id.split("/")
        if "containers" in parts:
            try:
                container_name = parts[parts.index("containers") + 1]
            except (IndexError, ValueError):
                pass
        if "storageAccounts" in parts:
            try:
                storage_account_name = parts[parts.index("storageAccounts") + 1]
            except (IndexError, ValueError):
                pass

    caller = event.get("callerIpAddress", "<UNKNOWN_CALLER>")
    return (
        f"Azure Storage Blob Container Modified: [{container_name}] "
        f"in [{storage_account_name}] by [{caller}]"
    )


def alert_context(event):
    context = azure_activity_alert_context(event)

    resource_id = event.get("resourceId", "")
    if resource_id:
        parts = resource_id.split("/")
        if "containers" in parts:
            try:
                context["container_name"] = parts[parts.index("containers") + 1]
            except (IndexError, ValueError):
                pass
        if "storageAccounts" in parts:
            try:
                context["storage_account_name"] = parts[parts.index("storageAccounts") + 1]
            except (IndexError, ValueError):
                pass

    return context
