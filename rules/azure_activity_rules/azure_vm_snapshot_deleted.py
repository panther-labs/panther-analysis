from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

SNAPSHOT_DELETE = "MICROSOFT.COMPUTE/SNAPSHOTS/DELETE"


def rule(event):
    return event.get("operationName", "").upper() == SNAPSHOT_DELETE and azure_activity_success(
        event
    )


def title(event):
    resource_id = event.get("resourceId", "<UNKNOWN_RESOURCE>")

    snapshot_name = "<UNKNOWN_SNAPSHOT>"
    if resource_id:
        parts = resource_id.split("/")
        if "snapshots" in parts:
            try:
                snapshot_name = parts[parts.index("snapshots") + 1]
            except (IndexError, ValueError):
                pass

    caller = event.get("callerIpAddress", "<UNKNOWN_CALLER>")

    return f"Azure VM Snapshot Deleted: [{snapshot_name}] from [{caller}]"


def alert_context(event):
    context = azure_activity_alert_context(event)

    resource_id = event.get("resourceId", "")
    if resource_id:
        parts = resource_id.split("/")
        if "snapshots" in parts:
            try:
                context["snapshot_name"] = parts[parts.index("snapshots") + 1]
            except (IndexError, ValueError):
                pass

    return context
