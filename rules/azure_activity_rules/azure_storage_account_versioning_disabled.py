from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

BLOB_SERVICES_WRITE = "MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/WRITE"


def rule(event):
    return all(
        [
            event.get("operationName", "").upper() == BLOB_SERVICES_WRITE,
            event.deep_get("properties", "requestbody", "properties", "isVersioningEnabled")
            is False,
            azure_activity_success(event),
        ]
    )


def title(event):
    storage_account = event.deep_get("resourceId", default="<UNKNOWN_ACCOUNT>")
    caller = event.deep_get("callerIpAddress", default="<UNKNOWN_CALLER>")

    return f"Azure Storage Account blob versioning disabled on [{storage_account}] from [{caller}]"


def alert_context(event):
    context = azure_activity_alert_context(event)
    context["is_versioning_enabled"] = event.deep_get(
        "properties",
        "requestbody",
        "properties",
        "isVersioningEnabled",
        default=None,
    )
    return context
