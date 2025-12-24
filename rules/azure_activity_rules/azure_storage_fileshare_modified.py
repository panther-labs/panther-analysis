from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

FILESHARE_OPERATIONS = [
    "MICROSOFT.STORAGE/STORAGEACCOUNTS/FILESERVICES/SHARES/WRITE",
]


def rule(event):
    return event.get(
        "operationName", ""
    ).upper() in FILESHARE_OPERATIONS and azure_activity_success(event)


def title(event):
    resource_id = event.get("resourceId", "<UNKNOWN_RESOURCE>")
    caller = event.get("callerIpAddress", "<UNKNOWN_CALLER>")

    # Extract file share name from resource ID
    share_name = "<UNKNOWN_SHARE>"
    if resource_id:
        parts = resource_id.split("/")
        if "shares" in parts:
            try:
                share_name = parts[parts.index("shares") + 1]
            except (IndexError, ValueError):
                pass

    return f"Azure Storage File Share Created or Modified: [{share_name}] by [{caller}]"


def alert_context(event):
    context = azure_activity_alert_context(event)

    resource_id = event.get("resourceId", "")
    if resource_id:
        parts = resource_id.split("/")

        # Extract file share name
        if "shares" in parts:
            try:
                context["share_name"] = parts[parts.index("shares") + 1]
            except (IndexError, ValueError):
                pass

        # Extract storage account name
        if "storageAccounts" in parts:
            try:
                context["storage_account"] = parts[parts.index("storageAccounts") + 1]
            except (IndexError, ValueError):
                pass

    return context
