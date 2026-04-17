from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    extract_resource_name_from_id,
)

STORAGE_ACCOUNT_DELETE = "MICROSOFT.STORAGE/STORAGEACCOUNTS/DELETE"


def rule(event):
    return event.get(
        "operationName", ""
    ).upper() == STORAGE_ACCOUNT_DELETE and azure_activity_success(event)


def title(event):
    resource_id = event.get("resourceId", "")
    storage_account = extract_resource_name_from_id(
        resource_id, "storageAccounts", default="<UNKNOWN_ACCOUNT>"
    )
    return f"Azure Storage Account [{storage_account}] deleted"


def alert_context(event):
    context = azure_activity_alert_context(event)
    return context
