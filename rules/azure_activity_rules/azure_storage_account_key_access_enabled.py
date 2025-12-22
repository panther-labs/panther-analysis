from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

STORAGE_ACCOUNT_WRITE = "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE"


def rule(event):
    return all(
        [
            event.get("operationName", "").upper() == STORAGE_ACCOUNT_WRITE,
            event.deep_get("properties", "requestbody", "properties", "allowSharedKeyAccess")
            is True,
            event.deep_get("properties", "requestbody", "location") is None,
            azure_activity_success(event),
        ]
    )


def title(event):
    storage_account = event.deep_get("resourceId", default="<UNKNOWN_ACCOUNT>")
    caller = event.deep_get("callerIpAddress", default="<UNKNOWN_CALLER>")

    return f"Azure Storage Account shared key access enabled on [{storage_account}] from [{caller}]"


def alert_context(event):
    context = azure_activity_alert_context(event)
    context["allow_shared_key_access"] = event.deep_get(
        "properties",
        "requestbody",
        "properties",
        "allowSharedKeyAccess",
        default=None,
    )
    return context
