from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

RESOURCE_GROUP_DELETE = "MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/DELETE"


def rule(event):
    return event.get(
        "operationName", ""
    ).upper() == RESOURCE_GROUP_DELETE and azure_activity_success(event)


def title(event):
    resource_group = event.deep_get("resourceId", default="<UNKNOWN_RESOURCE_GROUP>")
    caller = event.deep_get("callerIpAddress", default="<UNKNOWN_CALLER>")

    return f"Azure Resource Group [{resource_group}] deleted from [{caller}]"


def alert_context(event):
    return azure_activity_alert_context(event)
