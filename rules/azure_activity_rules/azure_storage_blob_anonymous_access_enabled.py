from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    azure_parse_json_string,
    extract_resource_name_from_id,
)

STORAGE_WRITE = "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE"
BLOB_SERVICES_WRITE = "MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/WRITE"
CONTAINERS_WRITE = "MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/WRITE"


def rule(event):
    if not azure_activity_success(event):
        return False

    operation = event.get("operationName", "").upper()
    requestbody = azure_parse_json_string(event.deep_get("properties", "requestbody", default=None))
    properties = requestbody.get("properties", {})

    # Check for storage account level - allowBlobPublicAccess
    if operation == STORAGE_WRITE:
        return properties.get("allowBlobPublicAccess") is True

    # Check for blob service or container level - publicAccess
    if operation in [BLOB_SERVICES_WRITE, CONTAINERS_WRITE]:
        return properties.get("publicAccess") in ["Blob", "Container"]

    return False


def title(event):
    resource_id = event.get("resourceId", "")
    caller = event.deep_get("callerIpAddress", default="<UNKNOWN_CALLER>")
    operation = event.get("operationName", "").upper()

    if operation == STORAGE_WRITE:
        storage_account = extract_resource_name_from_id(
            resource_id, "storageAccounts", default="<UNKNOWN_ACCOUNT>"
        )
        return (
            f"Azure Storage Account anonymous blob access enabled "
            f"on [{storage_account}] from [{caller}]"
        )

    # For container-level operations, try to extract container name
    container = extract_resource_name_from_id(
        resource_id, "containers", default="<UNKNOWN_CONTAINER>"
    )
    if container:
        storage_resource = container
    else:
        storage_resource = extract_resource_name_from_id(
            resource_id, "storageAccounts", default="<UNKNOWN_RESOURCE>"
        )

    requestbody = azure_parse_json_string(event.deep_get("properties", "requestbody", default=None))
    resource_type = requestbody.get("properties", {}).get("publicAccess", "")
    return (
        f"Azure Storage public access allowed on [{resource_type}] "
        f"for [{storage_resource}] from [{caller}]"
    )


def alert_context(event):
    context = azure_activity_alert_context(event)

    resource_id = event.get("resourceId", "")

    storage_account_name = extract_resource_name_from_id(resource_id, "storageAccounts", default="")
    if storage_account_name:
        context["storage_account_name"] = storage_account_name

    resource_group = extract_resource_name_from_id(resource_id, "resourceGroups", default="")
    if resource_group:
        context["resource_group"] = resource_group

    return context
