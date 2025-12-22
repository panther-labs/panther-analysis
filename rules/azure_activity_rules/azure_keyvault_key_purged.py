from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

KEYVAULT_KEY_PURGE = "MICROSOFT.KEYVAULT/VAULTS/KEYS/PURGE/ACTION"


def rule(event):
    return event.get("operationName", "").upper() == KEYVAULT_KEY_PURGE and azure_activity_success(
        event
    )


def title(event):
    keyvault = event.deep_get("resourceId", default="<UNKNOWN_KEYVAULT>")
    caller = event.deep_get("callerIpAddress", default="<UNKNOWN_CALLER>")

    return f"Azure Key Vault key permanently purged on [{keyvault}] from [{caller}]"


def alert_context(event):
    return azure_activity_alert_context(event)
