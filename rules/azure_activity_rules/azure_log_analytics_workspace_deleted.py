from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

WORKSPACE_DELETE = "MICROSOFT.OPERATIONALINSIGHTS/WORKSPACES/DELETE"


def rule(event):
    return event.get("operationName", "").upper() == WORKSPACE_DELETE and azure_activity_success(
        event
    )


def title(event):
    workspace = event.deep_get("resourceId", default="<UNKNOWN_WORKSPACE>")
    caller = event.deep_get("callerIpAddress", default="<UNKNOWN_CALLER>")

    return f"Azure Log Analytics Workspace deleted [{workspace}] from [{caller}]"


def alert_context(event):
    return azure_activity_alert_context(event)
