from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

CERTIFICATE_READ = "MICROSOFT.KEYVAULT/VAULTS/CERTIFICATES/READ"


def rule(event):
    operation = event.get("operationName", "").upper()
    return operation == CERTIFICATE_READ and azure_activity_success(event)


def title(event):
    vault_resource = event.deep_get("resourceId", default="<UNKNOWN_VAULT>")
    caller = event.deep_get("callerIpAddress", default="<UNKNOWN_CALLER>")

    return f"Azure Key Vault certificate accessed from [{vault_resource}] by [{caller}]"


def alert_context(event):
    context = azure_activity_alert_context(event)
    context["operation_type"] = "certificate_access"

    # Extract certificate name from resourceId
    resource_id = event.get("resourceId", "")
    if "/certificates/" in resource_id:
        certificate_name = resource_id.split("/certificates/")[-1]
        context["certificate_name"] = certificate_name

    return context
