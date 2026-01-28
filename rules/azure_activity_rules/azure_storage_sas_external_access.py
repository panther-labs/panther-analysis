import ipaddress
from urllib.parse import parse_qs, urlparse


def rule(event):
    """
    Detects SAS token usage from external IP addresses.
    Replicates Defender for Cloud: Storage.Blob_AccountSas.InternalSasUsedExternally
    """
    # Must be storage operation
    if event.get("category") not in ["StorageRead", "StorageWrite", "StorageDelete"]:
        return False

    # Must be successful
    status_code = event.get("statusCode")
    if status_code not in [200, 201, 202, 204]:
        return False

    # Check if SAS token was used (look for 'sig=' in URI)
    uri = event.get("uri", "")
    if not uri or "sig=" not in uri:
        return False

    # Check if IP is external (not private/RFC1918)
    caller_ip = event.get("callerIpAddress", "").split(":")[0]
    if not caller_ip or is_private_ip(caller_ip):
        return False

    return True


def is_private_ip(ip_address):
    """Check if IP is in private ranges (RFC1918) or localhost"""
    try:
        ip_obj = ipaddress.ip_address(ip_address)
        return ip_obj.is_private or ip_obj.is_loopback
    except ValueError:
        # If we can't parse the IP, treat it as suspicious (don't filter out)
        return False


def is_permissive_sas(uri):
    """
    Check if SAS token has write, delete, or add permissions.
    SAS permissions in 'sp' parameter: r=read, a=add, c=create, w=write, d=delete, l=list
    """
    if not uri:
        return True  # Unknown URIs treated as potentially permissive

    parsed = urlparse(uri)
    params = parse_qs(parsed.query)
    permissions = params.get("sp", [""])[0]

    # Check for dangerous permissions
    return any(perm in permissions for perm in ["w", "d", "a"])


def title(event):
    caller_ip = event.get("callerIpAddress", "<UNKNOWN_IP>").split(":")[0]
    storage_account = event.deep_get("properties", "accountName", default="<UNKNOWN_ACCOUNT>")
    operation = event.get("operationName", "<UNKNOWN_OPERATION>")

    return (
        f"Azure Storage SAS token used from external IP [{caller_ip}] "
        f"to access [{storage_account}] with operation [{operation}]"
    )


def severity(event):
    """Higher severity for write/delete operations"""
    operation = event.get("operationName", "").lower()

    # Check if this is a write/delete operation or has permissive SAS
    uri = event.get("uri", "")
    if is_permissive_sas(uri):
        return "HIGH"

    # Delete operations are always high severity
    if "delete" in operation:
        return "HIGH"

    # Write operations are medium severity
    if any(op in operation for op in ["put", "write", "create", "set"]):
        return "MEDIUM"

    # Read-only operations from external IPs are low severity
    return "LOW"


def alert_context(event):
    context = {
        "caller_ip": event.get("callerIpAddress", "<UNKNOWN_IP>").split(":")[0],
        "storage_account": event.deep_get("properties", "accountName", default="<UNKNOWN>"),
        "operation": event.get("operationName", "<UNKNOWN_OPERATION>"),
        "object_key": event.deep_get("properties", "objectKey", default="<UNKNOWN>"),
        "user_agent": event.deep_get("properties", "userAgentHeader", default="<UNKNOWN>"),
        "uri": event.get("uri", "<UNKNOWN_URI>"),
        "status_code": event.get("statusCode"),
        "category": event.get("category"),
    }

    # Extract SAS permissions if available
    uri = event.get("uri", "")
    if uri:
        parsed = urlparse(uri)
        params = parse_qs(parsed.query)
        if "sp" in params:
            context["sas_permissions"] = params["sp"][0]
        if "se" in params:
            context["sas_expiry"] = params["se"][0]

    return context


def dedup(event):
    """Group alerts by storage account and external IP"""
    caller_ip = event.get("callerIpAddress", "").split(":")[0]
    storage_account = event.deep_get("properties", "accountName", default="unknown")
    return f"{storage_account}:{caller_ip}"
