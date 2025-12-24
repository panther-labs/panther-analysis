from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

DIAGNOSTIC_SETTINGS_DELETE = "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE"


def rule(event):
    return event.get(
        "operationName", ""
    ).upper() == DIAGNOSTIC_SETTINGS_DELETE and azure_activity_success(event)


def title(event):
    resource = event.deep_get("resourceId", default="<UNKNOWN_RESOURCE>")
    caller = event.deep_get("callerIpAddress", default="<UNKNOWN_CALLER>")

    return f"Azure Diagnostic Settings deleted on [{resource}] from [{caller}]"


def alert_context(event):
    return azure_activity_alert_context(event)
