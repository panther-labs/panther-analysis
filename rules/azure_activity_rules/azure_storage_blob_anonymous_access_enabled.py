from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    azure_parse_requestbody,
)

STORAGE_WRITE = "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE"
BLOB_SERVICES_WRITE = "MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/WRITE"
CONTAINERS_WRITE = "MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/WRITE"


def rule(event):
    if not azure_activity_success(event):
        return False

    operation = event.get("operationName", "").upper()
    requestbody = azure_parse_requestbody(event)
    properties = requestbody.get("properties", {})

    # Check for storage account level - allowBlobPublicAccess
    if operation == STORAGE_WRITE:
        return properties.get("allowBlobPublicAccess") is True

    # Check for blob service or container level - publicAccess
    if operation in [BLOB_SERVICES_WRITE, CONTAINERS_WRITE]:
        return properties.get("publicAccess") in ["Blob", "Container"]

    return False


def title(event):
    storage_resource = event.deep_get("resourceId", default="<UNKNOWN_RESOURCE>")
    caller = event.deep_get("callerIpAddress", default="<UNKNOWN_CALLER>")
    operation = event.get("operationName", "").upper()

    if operation == STORAGE_WRITE:
        return (
            f"Azure Storage Account anonymous blob access enabled "
            f"on [{storage_resource}] from [{caller}]"
        )

    requestbody = azure_parse_requestbody(event)
    public_access = requestbody.get("properties", {}).get("publicAccess", "")
    return (
        f"Azure Storage Container public access set to [{public_access}] "
        f"on [{storage_resource}] from [{caller}]"
    )


def alert_context(event):
    context = azure_activity_alert_context(event)
    requestbody = azure_parse_requestbody(event)
    properties = requestbody.get("properties", {})
    operation = event.get("operationName", "").upper()

    if operation == STORAGE_WRITE:
        allow_blob_public_access = properties.get("allowBlobPublicAccess")
        if allow_blob_public_access is not None:
            context["allow_blob_public_access"] = allow_blob_public_access
    else:
        public_access = properties.get("publicAccess")
        if public_access:
            context["public_access"] = public_access

    return context
