from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    azure_parse_requestbody,
)

BLOB_SERVICES_WRITE = "MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/WRITE"


def rule(event):
    requestbody = azure_parse_requestbody(event)
    return all(
        [
            event.get("operationName", "").upper() == BLOB_SERVICES_WRITE,
            requestbody.get("properties", {})
            .get("containerDeleteRetentionPolicy", {})
            .get("enabled")
            is False,
            azure_activity_success(event),
        ]
    )


def title(event):
    storage_account = event.deep_get("resourceId", default="<UNKNOWN_ACCOUNT>")
    caller = event.deep_get("callerIpAddress", default="<UNKNOWN_CALLER>")

    return f"Azure Storage container soft delete disabled on [{storage_account}] from [{caller}]"


def alert_context(event):
    context = azure_activity_alert_context(event)
    requestbody = azure_parse_requestbody(event)
    context["container_delete_retention_policy"] = requestbody.get("properties", {}).get(
        "containerDeleteRetentionPolicy"
    )
    return context
