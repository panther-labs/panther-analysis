from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    extract_resource_name_from_id,
)

CERTIFICATE_READ = "MICROSOFT.KEYVAULT/VAULTS/CERTIFICATES/READ"


def rule(event):
    operation = event.get("operationName", "").upper()
    return operation == CERTIFICATE_READ and azure_activity_success(event)


def title(event):
    resource_id = event.get("resourceId", "")
    keyvault_name = extract_resource_name_from_id(resource_id, "vaults", default="UNKNOWN")

    caller = event.get("callerIpAddress", default="<UNKNOWN_CALLER>")

    return f"Azure Key Vault certificate accessed from [{keyvault_name}] by [{caller}]"


def alert_context(event):
    context = azure_activity_alert_context(event)

    resource_id = event.get("resourceId", "")

    keyvault_name = extract_resource_name_from_id(resource_id, "vaults", default="")
    if keyvault_name:
        context["keyvault_name"] = keyvault_name

    certificate_name = extract_resource_name_from_id(resource_id, "certificates", default="")
    if certificate_name:
        context["certificate_name"] = certificate_name

    return context
