from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    extract_resource_name_from_id,
)

SNAPSHOT_DELETE = "MICROSOFT.COMPUTE/SNAPSHOTS/DELETE"


def rule(event):
    return event.get("operationName", "").upper() == SNAPSHOT_DELETE and azure_activity_success(
        event
    )


def title(event):
    resource_id = event.get("resourceId", "")
    snapshot_name = extract_resource_name_from_id(
        resource_id, "snapshots", default="<UNKNOWN_SNAPSHOT>"
    )

    return f"Azure VM Snapshot [{snapshot_name}] deleted"


def alert_context(event):
    context = azure_activity_alert_context(event)

    resource_id = event.get("resourceId", "")

    snapshot_name = extract_resource_name_from_id(resource_id, "snapshots", default="")
    if snapshot_name:
        context["snapshot_name"] = snapshot_name

    resource_group = extract_resource_name_from_id(resource_id, "resourceGroups", default="")
    if resource_group:
        context["resource_group"] = resource_group

    return context
