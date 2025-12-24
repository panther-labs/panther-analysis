from panther_azureactivity_helpers import azure_activity_alert_context, azure_resource_logs_failure

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
    caller = event.get("callerIpAddress", "<UNKNOWN_CALLER>")
    storage_account = extract_storage_account(event.get("resourceId", ""))
    blob_path = event.deep_get("properties", "objectKey", default="<UNKNOWN_BLOB>")

    return (
        f"CPK-encrypted blob access denied in storage account [{storage_account}] "
        f"- {blob_path} from [{caller}]"
    )


def alert_context(event):
    context = azure_activity_alert_context(event)
    # Add blob-specific context
    context["blob_path"] = event.deep_get("properties", "objectKey", default="<UNKNOWN>")
    context["storage_account"] = extract_storage_account(event.get("resourceId", ""))
    context["user_agent"] = event.deep_get("properties", "userAgentHeader", default="<UNKNOWN>")
    context["status_code"] = event.get("statusCode", "<UNKNOWN>")
    context["status_text"] = event.get("statusText", "<UNKNOWN>")
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
