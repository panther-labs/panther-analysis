from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_resource_logs_failure,
    extract_resource_name_from_id,
)

STORAGE_READ_CATEGORY = "STORAGEREAD"
CPK_ERROR_STATUS = "BLOBUSESCUSTOMERSPECIFIEDENCRYPTION"


def rule(event):
    # Detect when users try to access CPK-encrypted blobs without the key
    return (
        event.get("category", "").upper() == STORAGE_READ_CATEGORY
        and event.get("statusCode") == 409
        and event.get("statusText", "").upper() == CPK_ERROR_STATUS
        and azure_resource_logs_failure(event)
    )


def title(event):
    resource_id = event.get("resourceId", "<UNKNOWN_STORAGE_ACCOUNT>")
    storage_account = extract_resource_name_from_id(
        resource_id, "storageAccounts", default="<UNKNOWN_STORAGE_ACCOUNT>"
    )
    blob_path = event.deep_get("properties", "objectKey", default="<UNKNOWN_BLOB>")

    return (
        f"Access denied returned in storage account [{storage_account}] "
        f"for CPK-encrypted blob [{blob_path}]"
    )


def alert_context(event):
    context = azure_activity_alert_context(event)
    # Add blob-specific context
    context["blob_path"] = event.deep_get("properties", "objectKey", default="<UNKNOWN>")
    context["user_agent"] = event.deep_get("properties", "userAgentHeader", default="<UNKNOWN>")
    context["status_code"] = event.get("statusCode", "<UNKNOWN>")
    context["status_text"] = event.get("statusText", "<UNKNOWN>")
    return context
