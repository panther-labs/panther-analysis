from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_resource_logs_success,
    extract_resource_name_from_id,
)


def rule(event):
    # Must be GetBlob operation (actual data retrieval)
    operation = event.get("operationName", "").upper()
    if operation != "GETBLOB":
        return False

    # Must be successful
    return azure_resource_logs_success(event)


def title(event):
    caller_ip = event.get("callerIpAddress", "<UNKNOWN_IP>").split(":")[0]
    resource_id = event.get("resourceId", "<UNKNOWN_STORAGE_ACCOUNT>")
    storage_account = extract_resource_name_from_id(
        resource_id, "storageAccounts", default="<UNKNOWN_ACCOUNT>"
    )

    return (
        f"Unusual volume of blobs extracted from Azure Storage account [{storage_account}] "
        f"by [{caller_ip}]"
    )


def dedup(event):
    """Group by storage account and caller IP for 15-minute aggregation"""
    caller_ip = event.get("callerIpAddress", "").split(":")[0]
    resource_id = event.get("resourceId", "")
    storage_account = extract_resource_name_from_id(
        resource_id, "storageAccounts", default="unknown"
    )
    return f"{storage_account}:{caller_ip}"


def severity(event):
    """Higher severity if user agent suggests automated exfiltration"""
    user_agent = event.deep_get("properties", "userAgentHeader", default="").lower()

    # Scripts, curl, wget suggest malicious automation
    suspicious_agents = ["python", "curl", "wget", "powershell", "bash", "script"]
    if any(agent in user_agent for agent in suspicious_agents):
        return "HIGH"

    return "MEDIUM"


def alert_context(event):
    context = azure_activity_alert_context(event)
    # Add blob-specific context
    context["blob_path"] = event.deep_get("properties", "objectKey", default="<UNKNOWN>")
    context["user_agent"] = event.deep_get("properties", "userAgentHeader", default="<UNKNOWN>")
    return context
