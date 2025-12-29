from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    extract_resource_name_from_id,
)

ACTION_GROUPS_DELETE = "MICROSOFT.INSIGHTS/ACTIONGROUPS/DELETE"


def rule(event):
    return event.get(
        "operationName", ""
    ).upper() == ACTION_GROUPS_DELETE and azure_activity_success(event)


def title(event):
    resource_id = event.get("resourceId", "")

    action_group = extract_resource_name_from_id(
        resource_id, "actionGroups", default="<UNKNOWN_ACTION_GROUP>"
    )
    return f"Azure Action Group deleted [{action_group}]"


def alert_context(event):
    context = azure_activity_alert_context(event)

    resource_id = event.get("resourceId", "")

    action_group_name = extract_resource_name_from_id(resource_id, "actionGroups", default="")
    if action_group_name:
        context["action_group_name"] = action_group_name

    resource_group = extract_resource_name_from_id(resource_id, "resourceGroups", default="")
    if resource_group:
        context["resource_group"] = resource_group

    return context
