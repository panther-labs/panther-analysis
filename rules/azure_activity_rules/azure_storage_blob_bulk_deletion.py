from panther_azureactivity_helpers import azure_activity_alert_context, azure_resource_logs_success


def rule(event):
    return event.get("operationName", "").upper() == "DELETEBLOB" and azure_resource_logs_success(
        event
    )


def title(event):
    caller = event.get("callerIpAddress", "<UNKNOWN_CALLER>")
    storage_account = extract_storage_account(event.get("resourceId", "<UNKNOWN_STORAGE_ACCOUNT>"))

    return f"Azure Blobs deleted from storage account [{storage_account}] by caller [{caller}]"


def alert_context(event):
    context = azure_activity_alert_context(event)
    # Add blob-specific context
    context["blob_path"] = event.deep_get("properties", "objectKey", default="<UNKNOWN>")
    context["storage_account"] = extract_storage_account(event.get("resourceId", ""))
    context["user_agent"] = event.deep_get("properties", "userAgentHeader", default="<UNKNOWN>")
    return context


def extract_storage_account(resource_id):
    if resource_id:
        # resourceId format: /subscriptions/.../storageAccounts/NAME/blobServices/...
        parts = resource_id.split("/")
        if "storageAccounts" in parts:
            idx = parts.index("storageAccounts")
            if idx + 1 < len(parts):
                return parts[idx + 1]
    return "<UNKNOWN_ACCOUNT>"
