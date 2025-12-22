from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

STORAGE_ACCOUNT_DELETE = "MICROSOFT.STORAGE/STORAGEACCOUNTS/DELETE"


def rule(event):
    return event.get(
        "operationName", ""
    ).upper() == STORAGE_ACCOUNT_DELETE and azure_activity_success(event)


def title(event):
    storage_account = event.deep_get("resourceId", default="<UNKNOWN_ACCOUNT>")
    caller = event.deep_get("callerIpAddress", default="<UNKNOWN_CALLER>")

    return f"Azure Storage Account [{storage_account}] deleted from [{caller}]"


def alert_context(event):
    return azure_activity_alert_context(event)
