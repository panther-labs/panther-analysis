from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    extract_resource_name_from_id,
)

VNET_DELETE = "MICROSOFT.NETWORK/VIRTUALNETWORKS/DELETE"


def rule(event):
    return event.get("operationName", "").upper() == VNET_DELETE and azure_activity_success(event)


def title(event):
    resource_id = event.get("resourceId", "")
    vnet = extract_resource_name_from_id(resource_id, "virtualNetworks", default="<UNKNOWN_VNET>")

    return f"Azure Virtual Network [{vnet}] deleted"


def alert_context(event):
    context = azure_activity_alert_context(event)

    resource_id = event.get("resourceId", "")

    vnet_name = extract_resource_name_from_id(resource_id, "virtualNetworks", default="")
    if vnet_name:
        context["vnet_name"] = vnet_name

    resource_group = extract_resource_name_from_id(resource_id, "resourceGroups", default="")
    if resource_group:
        context["resource_group"] = resource_group

    return context
