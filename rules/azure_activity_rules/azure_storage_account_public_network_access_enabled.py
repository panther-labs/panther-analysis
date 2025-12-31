from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    azure_parse_json_string,
    extract_resource_name_from_id,
)

STORAGE_ACCOUNT_WRITE = "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE"


def rule(event):
    requestbody = azure_parse_json_string(event.deep_get("properties", "requestbody", default=None))
    return all(
        [
            event.get("operationName", "").upper() == STORAGE_ACCOUNT_WRITE,
            requestbody.get("properties", {}).get("networkAcls", {}).get("defaultAction")
            == "Allow",
            requestbody.get("location") is None,
            azure_activity_success(event),
        ]
    )


def title(event):
    resource_id = event.get("resourceId", "")
    storage_account = extract_resource_name_from_id(
        resource_id, "storageAccounts", default="<UNKNOWN_ACCOUNT>"
    )

    return f"Azure Storage Account public network access enabled on [{storage_account}] "


def alert_context(event):
    context = azure_activity_alert_context(event)
    return context
