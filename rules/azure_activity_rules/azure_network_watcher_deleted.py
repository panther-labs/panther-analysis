from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

NETWORK_WATCHER_DELETE_OPERATION = "MICROSOFT.NETWORK/NETWORKWATCHERS/DELETE"


def rule(event):
    return all(
        [
            event.get("operationName", "").upper() == NETWORK_WATCHER_DELETE_OPERATION,
            azure_activity_success(event),
        ]
    )


def title(event):
    resource_id = event.get("resourceId", "<UNKNOWN_RESOURCE>")
    location = event.get("location", "<UNKNOWN_LOCATION>")
    return f"Azure Network Watcher Deleted in [{location}]: [{resource_id}]"


def alert_context(event):
    return azure_activity_alert_context(event)
