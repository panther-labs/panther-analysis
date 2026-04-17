from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    extract_resource_name_from_id,
)

EVENT_HUB_DELETE_OPERATION = "MICROSOFT.EVENTHUB/NAMESPACES/EVENTHUBS/DELETE"


def rule(event):
    return all(
        [
            event.get("operationName", "").upper() == EVENT_HUB_DELETE_OPERATION,
            azure_activity_success(event),
        ]
    )


def title(event):
    resource_id = event.get("resourceId", "")
    eventhub = extract_resource_name_from_id(resource_id, "eventhubs", default="<UNKNOWN_EVENTHUB>")
    return f"Azure Event Hub Deleted: [{eventhub}]"


def alert_context(event):
    context = azure_activity_alert_context(event)

    resource_id = event.get("resourceId", "")

    eventhub_name = extract_resource_name_from_id(resource_id, "eventhubs", default="")
    if eventhub_name:
        context["eventhub_name"] = eventhub_name

    namespace_name = extract_resource_name_from_id(resource_id, "namespaces", default="")
    if namespace_name:
        context["namespace_name"] = namespace_name

    resource_group = extract_resource_name_from_id(resource_id, "resourceGroups", default="")
    if resource_group:
        context["resource_group"] = resource_group

    return context
