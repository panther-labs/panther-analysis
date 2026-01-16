from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    extract_resource_name_from_id,
)

NETWORK_WATCHER_DELETE_OPERATION = "MICROSOFT.NETWORK/NETWORKWATCHERS/DELETE"


def rule(event):
    return all(
        [
            event.get("operationName", "").upper() == NETWORK_WATCHER_DELETE_OPERATION,
            azure_activity_success(event),
        ]
    )


def title(event):
    resource_id = event.get("resourceId", "")
    network_watcher = extract_resource_name_from_id(
        resource_id, "networkWatchers", default="<UNKNOWN_WATCHER>"
    )
    return f"Azure Network Watcher [{network_watcher}] Deleted"


def alert_context(event):
    context = azure_activity_alert_context(event)

    resource_id = event.get("resourceId", "")

    network_watcher_name = extract_resource_name_from_id(resource_id, "networkWatchers", default="")
    if network_watcher_name:
        context["network_watcher_name"] = network_watcher_name

    resource_group = extract_resource_name_from_id(resource_id, "resourceGroups", default="")
    if resource_group:
        context["resource_group"] = resource_group

    return context
