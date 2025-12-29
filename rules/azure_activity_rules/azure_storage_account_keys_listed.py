from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    extract_resource_name_from_id,
)

KEY_LIST_OPERATIONS = [
    "MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION",
]


def rule(event):
    return event.get("operationName", "").upper() in KEY_LIST_OPERATIONS and azure_activity_success(
        event
    )


def title(event):
    caller = event.deep_get("callerIpAddress", default="<UNKNOWN_CALLER>")
    resource_id = event.get("resourceId", "")
    storage_account_name = extract_resource_name_from_id(
        resource_id, "storageAccounts", default="<UNKNOWN_STORAGE_ACCOUNT>"
    )

    return f"Azure Storage Account Keys Listed: [{storage_account_name}] by [{caller}]"


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
