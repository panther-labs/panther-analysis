from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

DISK_SAS_OPERATIONS = [
    "MICROSOFT.COMPUTE/DISKS/BEGINGETACCESS/ACTION",
]


def rule(event):
    return event.get("operationName", "").upper() in DISK_SAS_OPERATIONS and azure_activity_success(
        event
    )


def title(event):
    resource_id = event.get("resourceId", "<UNKNOWN_RESOURCE>")
    caller = event.get("callerIpAddress", "<UNKNOWN_CALLER>")

    # Extract disk name from resource ID
    disk_name = "<UNKNOWN_DISK>"
    if resource_id:
        parts = resource_id.split("/")
        if "disks" in parts:
            try:
                disk_name = parts[parts.index("disks") + 1]
            except (IndexError, ValueError):
                pass

    return f"Azure VM Disk SAS URI Generated: [{disk_name}] by [{caller}]"


def alert_context(event):
    context = azure_activity_alert_context(event)

    resource_id = event.get("resourceId", "")
    if resource_id:
        parts = resource_id.split("/")

        # Extract disk name
        if "disks" in parts:
            try:
                context["disk_name"] = parts[parts.index("disks") + 1]
            except (IndexError, ValueError):
                pass

        # Extract resource group
        if "resourceGroups" in parts:
            try:
                context["resource_group"] = parts[parts.index("resourceGroups") + 1]
            except (IndexError, ValueError):
                pass

    return context
