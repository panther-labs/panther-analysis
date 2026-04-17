from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    extract_resource_name_from_id,
)

IMMUTABILITY_POLICY_DELETE = (
    "MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/IMMUTABILITYPOLICIES/DELETE"
)


def rule(event):
    return event.get(
        "operationName", ""
    ).upper() == IMMUTABILITY_POLICY_DELETE and azure_activity_success(event)


def title(event):
    resource_id = event.get("resourceId", "")
    container_name = extract_resource_name_from_id(
        resource_id, "containers", default="<UNKNOWN_CONTAINER>"
    )
    storage_account = extract_resource_name_from_id(
        resource_id, "storageAccounts", default="<UNKNOWN_STORAGE_ACCOUNT>"
    )

    return (
        f"Azure Storage immutability policy deleted on container [{container_name}] "
        f"in storage account [{storage_account}]"
    )


def alert_context(event):
    context = azure_activity_alert_context(event)

    resource_id = event.get("resourceId", "")

    container_name = extract_resource_name_from_id(resource_id, "containers", default="")
    if container_name:
        context["container_name"] = container_name

    storage_account = extract_resource_name_from_id(resource_id, "storageAccounts", default="")
    if storage_account:
        context["storage_account"] = storage_account

    resource_group = extract_resource_name_from_id(resource_id, "resourceGroups", default="")
    if resource_group:
        context["resource_group"] = resource_group

    return context
