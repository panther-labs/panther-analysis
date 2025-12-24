from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    azure_parse_requestbody,
)

REGENERATE_KEY = "MICROSOFT.STORAGE/STORAGEACCOUNTS/REGENERATEKEY/ACTION"


def rule(event):
    return event.get("operationName", "").upper() == REGENERATE_KEY and azure_activity_success(
        event
    )


def title(event):
    storage_account = event.deep_get("resourceId", default="<UNKNOWN_ACCOUNT>")
    caller = event.deep_get("callerIpAddress", default="<UNKNOWN_CALLER>")
    requestbody = azure_parse_requestbody(event)
    key = requestbody.get("keyName", "<UNKNOWN_KEY>")
    return f"Azure Storage Account key [{key}] regenerated on [{storage_account}] from [{caller}]"


def alert_context(event):
    context = azure_activity_alert_context(event)
    requestbody = azure_parse_requestbody(event)
    context["key_name"] = requestbody.get("keyName", "<UNKNOWN_KEY>")
    return context
