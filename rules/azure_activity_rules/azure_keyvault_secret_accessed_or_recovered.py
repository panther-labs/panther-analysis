from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    extract_resource_name_from_id,
)

SECRET_GET = "MICROSOFT.KEYVAULT/VAULTS/SECRETS/GETSECRET/ACTION"  # nosec B105
SECRET_RECOVER = "MICROSOFT.KEYVAULT/VAULTS/SECRETS/RECOVER/ACTION"  # nosec B105
SECRET_RESTORE = "MICROSOFT.KEYVAULT/VAULTS/SECRETS/RESTORE/ACTION"  # nosec B105


def rule(event):
    operation = event.get("operationName", "").upper()
    return all(
        [
            operation in [SECRET_GET, SECRET_RECOVER, SECRET_RESTORE],
            azure_activity_success(event),
        ]
    )


def title(event):
    operation = event.get("operationName", "").upper()
    resource_id = event.get("resourceId", "")
    keyvault_name = extract_resource_name_from_id(resource_id, "vaults", default="")
    caller = event.get("callerIpAddress", default="<UNKNOWN_CALLER>")

    if operation == SECRET_RECOVER:
        return (
            f"Azure Key Vault soft-deleted secret recovered "
            f"from [{keyvault_name}] by [{caller}]"
        )

    return f"Azure Key Vault secret accessed from [{keyvault_name}] by [{caller}]"


def severity(event):
    operation = event.get("operationName", "").upper()
    # Recovering soft-deleted secrets is more suspicious
    if operation == SECRET_RECOVER:
        return "MEDIUM"
    return "DEFAULT"


def alert_context(event):
    context = azure_activity_alert_context(event)
    resource_id = event.get("resourceId", "")

    keyvault_name = extract_resource_name_from_id(resource_id, "vaults", default="")
    if keyvault_name:
        context["keyvault_name"] = keyvault_name

    secret_name = extract_resource_name_from_id(resource_id, "secrets", default="")
    if secret_name:
        context["secret_name"] = secret_name

    return context
