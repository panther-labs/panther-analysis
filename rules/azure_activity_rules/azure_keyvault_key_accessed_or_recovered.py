from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    extract_resource_name_from_id,
)

KEY_READ = "MICROSOFT.KEYVAULT/VAULTS/KEYS/READ/ACTION"
KEY_RESTORED = "MICROSOFT.KEYVAULT/VAULTS/KEYS/RESTORE/ACTION"
KEY_RECOVERED = "MICROSOFT.KEYVAULT/VAULTS/KEYS/RECOVER/ACTION"


def rule(event):
    operation = event.get("operationName", "").upper()
    return operation in [KEY_READ, KEY_RESTORED, KEY_RECOVERED] and azure_activity_success(event)


def title(event):
    resource_id = event.get("resourceId", "")
    keyvault_name = extract_resource_name_from_id(resource_id, "vaults", default="")
    caller = event.get("callerIpAddress", default="<UNKNOWN_CALLER>")
    operation = event.get("operationName", "").upper()
    action = None
    if operation == KEY_READ:
        action = "read"
    elif operation == KEY_RESTORED:
        action = "restored"
    elif operation == KEY_RECOVERED:
        action = "recovered"
    if action is not None:
        return f"Azure Key Vault key {action} from [{keyvault_name}] by [{caller}]"
    return f"Azure Key Vault key accessed from [{keyvault_name}] by [{caller}]"


def alert_context(event):
    context = azure_activity_alert_context(event)
    resource_id = event.get("resourceId", "")
    keyvault_name = extract_resource_name_from_id(resource_id, "vaults", default="")
    if keyvault_name:
        context["keyvault_name"] = keyvault_name

    key_name = extract_resource_name_from_id(resource_id, "keys", default="")
    if key_name:
        context["key_name"] = key_name

    return context
