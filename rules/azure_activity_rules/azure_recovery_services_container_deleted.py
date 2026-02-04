from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    extract_resource_name_from_id,
)

PROTECTION_CONTAINER_DELETE = (
    "MICROSOFT.RECOVERYSERVICES/VAULTS/BACKUPFABRICS/PROTECTIONCONTAINERS/DELETE"
)


def rule(event):
    return event.get(
        "operationName", ""
    ).upper() == PROTECTION_CONTAINER_DELETE and azure_activity_success(event)


def title(event):
    resource_id = event.get("resourceId", "")
    vault_name = extract_resource_name_from_id(resource_id, "vaults", default="<UNKNOWN_VAULT>")
    container_name = extract_resource_name_from_id(
        resource_id, "protectionContainers", default="<UNKNOWN_CONTAINER>"
    )

    return (
        f"Azure Recovery Services protection container [{container_name}] "
        f"deleted from vault [{vault_name}]"
    )


def alert_context(event):
    context = azure_activity_alert_context(event)

    resource_id = event.get("resourceId", "")

    vault_name = extract_resource_name_from_id(resource_id, "vaults", default="")
    if vault_name:
        context["vault_name"] = vault_name

    container_name = extract_resource_name_from_id(resource_id, "protectionContainers", default="")
    if container_name:
        context["protection_container"] = container_name

    fabric_name = extract_resource_name_from_id(resource_id, "backupFabrics", default="")
    if fabric_name:
        context["backup_fabric"] = fabric_name

    resource_group = extract_resource_name_from_id(resource_id, "resourceGroups", default="")
    if resource_group:
        context["resource_group"] = resource_group

    return context
