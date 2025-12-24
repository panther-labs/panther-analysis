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
            requestbody.get("properties", {}).get("networkAcls", {}).get("defaultAction")
            == "Allow",
            requestbody.get("location") is None,
            azure_activity_success(event),
        ]
    )


def title(event):
    storage_account = event.deep_get("resourceId", default="<UNKNOWN_ACCOUNT>")
    caller = event.deep_get("callerIpAddress", default="<UNKNOWN_CALLER>")

    return (
        f"Azure Storage Account public network access enabled on [{storage_account}] "
        f"from [{caller}]"
    )


def alert_context(event):
    context = azure_activity_alert_context(event)
    # Add storage-specific network ACLs information
    requestbody = azure_parse_requestbody(event)
    context["network_acls"] = requestbody.get("properties", {}).get("networkAcls", {})
    return context
