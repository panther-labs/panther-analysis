from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

KEY_READ = "MICROSOFT.KEYVAULT/VAULTS/KEYS/READ"


def rule(event):
    operation = event.get("operationName", "").upper()
    return operation == KEY_READ and azure_activity_success(event)


def title(event):
    vault_resource = event.deep_get("resourceId", default="<UNKNOWN_VAULT>")
    caller = event.deep_get("callerIpAddress", default="<UNKNOWN_CALLER>")

    return f"Azure Key Vault key accessed from [{vault_resource}] by [{caller}]"


def alert_context(event):
    context = azure_activity_alert_context(event)
    context["operation_type"] = "key_access"

    # Extract key name from resourceId
    resource_id = event.get("resourceId", "")
    if "/keys/" in resource_id:
        key_name = resource_id.split("/keys/")[-1]
        context["key_name"] = key_name

    return context
