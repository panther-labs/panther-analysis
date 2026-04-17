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


def extract_caller_ip(event):
    """Extract IP address from callerIpAddress field, removing port if present"""
    caller_ip_address = event.get("callerIpAddress", "")
    if not caller_ip_address:
        return ""
    # Split by colon to remove port if present
    return caller_ip_address.split(":")[0] if ":" in caller_ip_address else caller_ip_address


def title(event):
    caller_ip = extract_caller_ip(event) or "<UNKNOWN_IP>"
    resource_id = event.get("resourceId", "")
    storage_account = (
        extract_resource_name_from_id(resource_id, "storageAccounts", default="<UNKNOWN_ACCOUNT>")
        if resource_id
        else "<UNKNOWN_ACCOUNT>"
    )

    return (
        f"Unusual volume of blobs extracted from Azure Storage account [{storage_account}] "
        f"by [{caller_ip}]"
    )


def dedup(event):
    """Group by storage account and caller IP for 15-minute aggregation"""
    caller_ip = extract_caller_ip(event) or "unknown"
    resource_id = event.get("resourceId", "")
    storage_account = (
        extract_resource_name_from_id(resource_id, "storageAccounts", default="unknown")
        if resource_id
        else "unknown"
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
