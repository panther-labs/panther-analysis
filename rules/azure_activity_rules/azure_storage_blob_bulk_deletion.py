from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_resource_logs_success,
    extract_resource_name_from_id,
)


def rule(event):
    return event.get("operationName", "").upper() == "DELETEBLOB" and azure_resource_logs_success(
        event
    )


def title(event):
    caller = event.get("callerIpAddress", "<UNKNOWN_CALLER>")
    resource_id = event.get("resourceId", "<UNKNOWN_STORAGE_ACCOUNT>")
    storage_account_name = extract_resource_name_from_id(
        resource_id, "storageAccounts", default="<UNKNOWN_STORAGE_ACCOUNT>"
    )
    return f"Azure Blobs deleted from storage account [{storage_account_name}] by caller [{caller}]"


def alert_context(event):
    context = azure_activity_alert_context(event)
    # Add blob-specific context
    context["blob_path"] = event.deep_get("properties", "objectKey", default="<UNKNOWN>")
    context["user_agent"] = event.deep_get("properties", "userAgentHeader", default="<UNKNOWN>")
    return context
