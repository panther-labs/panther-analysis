from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    extract_resource_name_from_id,
)

VIRTUAL_MACHINE_DELETE = "MICROSOFT.COMPUTE/VIRTUALMACHINES/DELETE"


def rule(event):
    return event.get(
        "operationName", ""
    ).upper() == VIRTUAL_MACHINE_DELETE and azure_activity_success(event)


def title(event):
    resource_id = event.get("resourceId", "")
    vmname = extract_resource_name_from_id(resource_id, "virtualMachines", default="<UNKNOWN_VM>")

    return f"Azure Virtual Machine [{vmname}] deleted"


def alert_context(event):
    context = azure_activity_alert_context(event)

    resource_id = event.get("resourceId", "")

    resource_group = extract_resource_name_from_id(resource_id, "resourceGroups", default="")
    if resource_group:
        context["resource_group"] = resource_group

    return context
