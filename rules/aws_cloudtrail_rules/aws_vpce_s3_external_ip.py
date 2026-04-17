import ipaddress

from panther_aws_helpers import aws_rule_context

# Define S3 data access operations
S3_DATA_ACCESS_OPERATIONS = [
    "GetObject",
    "GetObjectVersion",
    "GetObjectAcl",
    "GetObjectVersionAcl",
    "PutObject",
    "PutObjectAcl",
    "PutObjectVersionAcl",
    "CopyObject",
    "DeleteObject",
    "DeleteObjects",
    "DeleteObjectVersion",
]


def rule(event):
    # Check if this is a VPC Endpoint network activity event for S3
    if (
        event.get("eventType") != "AwsVpceEvent"
        or event.get("eventCategory") != "NetworkActivity"
        or event.get("eventSource") != "s3.amazonaws.com"
    ):
        return False

    # Focus on data access operations
    if event.get("eventName") not in S3_DATA_ACCESS_OPERATIONS:
        return False

    # Check for external IP
    source_ip = event.get("sourceIPAddress", "")
    if not source_ip:
        return False

    try:
        ip_obj = ipaddress.ip_address(source_ip)
        if ip_obj.is_global:
            return True
    except ValueError:
        # If source_ip is not a valid IP address
        pass

    return False


def title(event):
    # Use UDM actor_user which leverages the get_actor_user helper function
    actor_user = event.udm("actor_user")
    source_ip = event.get("sourceIPAddress", "unknown")
    bucket_name = event.deep_get("requestParameters", "bucketName", default="unknown")

    return (
        f"S3 Access via VPC Endpoint from External IP: [{actor_user}] from "
        f"[{source_ip}] to bucket [{bucket_name}]"
    )


def alert_context(event):
    account_id = event.deep_get("userIdentity", "accountId", default="")

    context = aws_rule_context(event)
    context.update(
        {
            "account_id": account_id,
            "principal_id": event.deep_get("userIdentity", "principalId", default="unknown"),
            "actor_user": event.udm("actor_user"),
            "source_ip": event.get("sourceIPAddress", "unknown"),
            "event_source": event.get("eventSource", "unknown"),
            "api_call": event.get("eventName", "unknown"),
            "resources": event.get("resources", []),
            "request_parameters": event.get("requestParameters", {}),
            "config": {
                "operations_monitored": S3_DATA_ACCESS_OPERATIONS,
            },
        }
    )

    return context
