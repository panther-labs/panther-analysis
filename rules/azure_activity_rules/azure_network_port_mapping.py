from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

NETWORK_READ = "MICROSOFT.NETWORK/NETWORKSECURITYGROUP/READ"


def rule(event):
    return all(
        [
            event.get("operationName", "").upper() == NETWORK_READ,
            azure_activity_success(event),
        ]
    )


def title(event):
    resource_id = event.get("resourceId", "<UNKNOWN_RESOURCE>")
    return f"Azure Excessive Network Read on [{resource_id}]"


def alert_context(event):
    return azure_activity_alert_context(event)
