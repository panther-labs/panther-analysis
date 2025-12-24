from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

ACTION_GROUPS_DELETE = "MICROSOFT.INSIGHTS/ACTIONGROUPS/DELETE"


def rule(event):
    return event.get(
        "operationName", ""
    ).upper() == ACTION_GROUPS_DELETE and azure_activity_success(event)


def title(event):
    action_group = event.deep_get("resourceId", default="<UNKNOWN_ACTION_GROUP>")
    caller = event.deep_get("callerIpAddress", default="<UNKNOWN_CALLER>")

    return f"Azure Action Group deleted [{action_group}] from [{caller}]"


def alert_context(event):
    return azure_activity_alert_context(event)
