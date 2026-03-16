from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    extract_resource_name_from_id,
)

DISK_SAS_OPERATIONS = [
    "MICROSOFT.COMPUTE/DISKS/BEGINGETACCESS/ACTION",
]


def rule(event):
    return event.get("operationName", "").upper() in DISK_SAS_OPERATIONS and azure_activity_success(
        event
    )


def title(event):
    resource_id = event.get("resourceId", "<UNKNOWN_RESOURCE>")

    disk_name = extract_resource_name_from_id(resource_id, "disks", default="<UNKNOWN_DISK>")

    return f"Azure VM Disk SAS URI Generated: [{disk_name}]"


def alert_context(event):
    context = azure_activity_alert_context(event)

    resource_id = event.get("resourceId", "")

    disk_name = extract_resource_name_from_id(resource_id, "disks", default="")
    if disk_name:
        context["disk_name"] = disk_name

    resource_group = extract_resource_name_from_id(resource_id, "resourceGroups", default="")
    if resource_group:
        context["resource_group"] = resource_group

    return context
