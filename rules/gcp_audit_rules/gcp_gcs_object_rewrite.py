import re

# User agent patterns indicating object rewrite
ENCRYPTION_REWRITE_PATTERNS = [
    re.compile(r"command/rewrite-k", re.IGNORECASE),  # gsutil rewrite -k
    re.compile(r"command/rewrite-k-s", re.IGNORECASE),  # gsutil rewrite -k -s
    re.compile(r"gsutil.*rewrite", re.IGNORECASE),  # gsutil rewrite variant
]


def rule(event):
    if event.deep_get("protoPayload", "serviceName") != "storage.googleapis.com":
        return False

    # Focus on the create operation (the actual re-encryption)
    method = event.deep_get("protoPayload", "methodName", default="")
    if method not in ["storage.objects.create"]:
        return False

    # This field contains commands executed on cli
    user_agent = event.deep_get(
        "protoPayload", "requestMetadata", "callerSuppliedUserAgent", default="<UNKNOWN_USER_AGENT>"
    )

    # Check for rewrite with encryption key change
    for pattern in ENCRYPTION_REWRITE_PATTERNS:
        if pattern.search(user_agent):
            return True

    return False


def title(event):
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="Unknown"
    )
    resource = event.deep_get("protoPayload", "resourceName", default="")
    obj_name = resource.split("/objects/")[-1] if "/objects/" in resource else "Unknown"
    bucket = event.deep_get("resource", "labels", "bucket_name", default="Unknown")
    return f"GCS object [{obj_name}] re-encryption in [{bucket}] by [{actor}]"


def dedup(event):
    # Dedupe by bucket and actor to group related re-encryption operations
    bucket = event.deep_get("resource", "labels", "bucket_name", default="unknown")
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="unknown"
    )
    return f"{bucket}-{actor}"


def alert_context(event):
    resource = event.deep_get("protoPayload", "resourceName", default="")
    return {
        "actor": event.deep_get("protoPayload", "authenticationInfo", "principalEmail"),
        "method": event.deep_get("protoPayload", "methodName"),
        "bucket": event.deep_get("resource", "labels", "bucket_name"),
        "object": resource.split("/objects/")[-1] if "/objects/" in resource else resource,
        "user_agent": event.deep_get("protoPayload", "requestMetadata", "callerSuppliedUserAgent"),
        "source_ip": event.deep_get("protoPayload", "requestMetadata", "callerIp"),
        "project": event.deep_get("resource", "labels", "project_id"),
    }
