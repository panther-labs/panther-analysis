from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    azure_parse_requestbody,
)

STORAGE_ACCOUNT_WRITE = "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE"


def rule(event):
    requestbody = azure_parse_requestbody(event)
    return all(
        [
            event.get("operationName", "").upper() == STORAGE_ACCOUNT_WRITE,
            requestbody.get("properties", {}).get("allowSharedKeyAccess") is True,
            requestbody.get("location") is None,
            azure_activity_success(event),
        ]
    )


def title(event):
    storage_account = event.deep_get("resourceId", default="<UNKNOWN_ACCOUNT>")
    caller = event.deep_get("callerIpAddress", default="<UNKNOWN_CALLER>")

    return f"Azure Storage Account shared key access enabled on [{storage_account}] from [{caller}]"


def alert_context(event):
    context = azure_activity_alert_context(event)
    requestbody = azure_parse_requestbody(event)
    context["allow_shared_key_access"] = requestbody.get("properties", {}).get(
        "allowSharedKeyAccess"
    )
    return context
