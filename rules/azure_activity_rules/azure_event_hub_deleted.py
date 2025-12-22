from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

EVENT_HUB_DELETE_OPERATION = "MICROSOFT.EVENTHUB/NAMESPACES/EVENTHUBS/DELETE"


def rule(event):
    return all(
        [
            event.get("operationName", "").upper() == EVENT_HUB_DELETE_OPERATION,
            azure_activity_success(event),
        ]
    )


def title(event):
    resource_id = event.get("resourceId", "<UNKNOWN_RESOURCE>")
    return f"Azure Event Hub Deleted: [{resource_id}]"


def alert_context(event):
    return azure_activity_alert_context(event)
