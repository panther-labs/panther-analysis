from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    extract_resource_name_from_id,
)

KEYVAULT_DELETE = "MICROSOFT.KEYVAULT/VAULTS/DELETE"


def rule(event):
    return event.get("operationName", "").upper() == KEYVAULT_DELETE and azure_activity_success(
        event
    )


def title(event):
    resource_id = event.get("resourceId", "")
    keyvault = extract_resource_name_from_id(resource_id, "vaults", default="<UNKNOWN_KEYVAULT>")
    caller = event.get("callerIpAddress", default="<UNKNOWN_CALLER>")

    return f"Azure Key Vault deleted [{keyvault}] from [{caller}]"


def alert_context(event):
    context = azure_activity_alert_context(event)

    resource_id = event.get("resourceId", "")
    keyvault_name = extract_resource_name_from_id(resource_id, "vaults", default="")
    if keyvault_name:
        context["keyvault_name"] = keyvault_name

    return context
