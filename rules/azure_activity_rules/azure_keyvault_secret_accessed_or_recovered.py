from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

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
    vault_resource = event.deep_get("resourceId", default="<UNKNOWN_VAULT>")
    caller = event.deep_get("callerIpAddress", default="<UNKNOWN_CALLER>")

    if operation == SECRET_RECOVER:
        return (
            f"Azure Key Vault soft-deleted secret recovered "
            f"from [{vault_resource}] by [{caller}]"
        )

    return f"Azure Key Vault secret accessed from [{vault_resource}] by [{caller}]"


def severity(event):
    operation = event.get("operationName", "").upper()
    # Recovering soft-deleted secrets is more suspicious
    if operation == SECRET_RECOVER:
        return "HIGH"
    return "DEFAULT"


def alert_context(event):
    context = azure_activity_alert_context(event)
    operation = event.get("operationName", "").upper()
    context["operation_type"] = (
        "secret_recovery" if operation == SECRET_RECOVER else "secret_access"
    )

    # Extract secret name from resourceId
    resource_id = event.get("resourceId", "")
    if "/secrets/" in resource_id:
        secret_name = resource_id.split("/secrets/")[-1]
        context["secret_name"] = secret_name

    return context
