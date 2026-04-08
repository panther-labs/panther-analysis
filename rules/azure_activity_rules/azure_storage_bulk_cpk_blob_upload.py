from panther_azureactivity_helpers import azure_resource_logs_success, extract_resource_name_from_id


def rule(event):
    return event.get("operationName", "").upper() == "PUTBLOB" and azure_resource_logs_success(
        event
    )


def unique(event):
    return event.deep_get("properties", "objectKey", default="UNKNOWN_BLOB")


def dedup(event):
    account = event.deep_get("properties", "accountName", default="UNKNOWN_ACCOUNT")
    # callerIpAddress is formatted as ip:port — strip port for grouping
    caller_ip = event.get("callerIpAddress", "UNKNOWN_IP").rsplit(":", 1)[0]
    return f"{account}:{caller_ip}"


def title(event):
    resource_id = event.get("resourceId", "")
    account = extract_resource_name_from_id(
        resource_id,
        "storageAccounts",
        default=event.deep_get("properties", "accountName", default="UNKNOWN_ACCOUNT"),
    )
    caller_ip = event.get("callerIpAddress", "UNKNOWN_IP").rsplit(":", 1)[0]
    return (
        f"[Azure] Bulk blob re-encryption detected in storage account [{account}] "
        f"from [{caller_ip}]"
    )


def alert_context(event):
    resource_id = event.get("resourceId", "")
    return {
        "storage_account": extract_resource_name_from_id(
            resource_id,
            "storageAccounts",
            default=event.deep_get("properties", "accountName", default="UNKNOWN_ACCOUNT"),
        ),
        "caller_ip": event.get("callerIpAddress", "UNKNOWN_IP").rsplit(":", 1)[0],
        "blob_path": event.deep_get("properties", "objectKey", default="UNKNOWN_BLOB"),
        "user_agent": event.deep_get("properties", "userAgentHeader", default="UNKNOWN"),
    }
