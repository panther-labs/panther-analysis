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
    resource_id = event.get("resourceId", "")
    storage_account_name = extract_resource_name_from_id(
        resource_id, "storageAccounts", default="<UNKNOWN_STORAGE_ACCOUNT>"
    )

    return f"Azure Storage Account Keys Listed on [{storage_account_name}]"


def alert_context(event):
    context = azure_activity_alert_context(event)
    return context
