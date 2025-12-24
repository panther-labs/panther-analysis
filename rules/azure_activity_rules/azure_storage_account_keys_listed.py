from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

KEY_LIST_OPERATIONS = [
    "MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION",
]


def rule(event):
    return event.get("operationName", "").upper() in KEY_LIST_OPERATIONS and azure_activity_success(
        event
    )


def title(event):
    caller = event.deep_get("identity", "claims", "ipaddr", default="<UNKNOWN_IP>")
    resource_id = event.get("resourceId", "")
    storage_account_name = "<UNKNOWN_STORAGE_ACCOUNT>"

    if resource_id:
        parts = resource_id.split("/")
        if "storageAccounts" in parts:
            try:
                storage_account_name = parts[parts.index("storageAccounts") + 1]
            except (ValueError, IndexError):
                pass

    return f"Azure Storage Account Keys Listed: [{storage_account_name}] by [{caller}]"


def alert_context(event):
    context = azure_activity_alert_context(event)
    resource_id = event.get("resourceId", "")

    if resource_id:
        parts = resource_id.split("/")
        if "storageAccounts" in parts:
            try:
                storage_account_name = parts[parts.index("storageAccounts") + 1]
                context["storage_account_name"] = storage_account_name
            except (ValueError, IndexError):
                pass

        if "resourceGroups" in parts:
            try:
                resource_group = parts[parts.index("resourceGroups") + 1]
                context["resource_group"] = resource_group
            except (ValueError, IndexError):
                pass

    context["operation_type"] = "storage_account_key_listing"

    return context
