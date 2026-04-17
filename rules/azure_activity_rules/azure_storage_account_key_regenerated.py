from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    azure_parse_json_string,
    extract_resource_name_from_id,
)

REGENERATE_KEY = "MICROSOFT.STORAGE/STORAGEACCOUNTS/REGENERATEKEY/ACTION"


def rule(event):
    return event.get("operationName", "").upper() == REGENERATE_KEY and azure_activity_success(
        event
    )


def title(event):
    resource_id = event.get("resourceId", "")
    storage_account = extract_resource_name_from_id(
        resource_id, "storageAccounts", default="<UNKNOWN_ACCOUNT>"
    )
    requestbody = azure_parse_json_string(event.deep_get("properties", "requestbody", default=None))
    key = requestbody.get("keyName", "<UNKNOWN_KEY>")
    return f"Azure Storage Account key [{key}] regenerated on [{storage_account}]"


def alert_context(event):
    context = azure_activity_alert_context(event)
    requestbody = azure_parse_json_string(event.deep_get("properties", "requestbody", default=None))
    context["key_name"] = requestbody.get("keyName", "<UNKNOWN_KEY>")
    return context
