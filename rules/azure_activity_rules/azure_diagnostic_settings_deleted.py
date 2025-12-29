from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    extract_resource_name_from_id,
)

DIAGNOSTIC_SETTINGS_DELETE = "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE"


def rule(event):
    return event.get(
        "operationName", ""
    ).upper() == DIAGNOSTIC_SETTINGS_DELETE and azure_activity_success(event)


def title(event):
    resource_id = event.get("resourceId", "")
    resource = extract_resource_name_from_id(
        resource_id, "diagnosticSettings", default="<UNKNOWN_RESOURCE>"
    )

    return f"Azure Diagnostic Settings deleted on [{resource}]"


def alert_context(event):
    context = azure_activity_alert_context(event)

    resource_id = event.get("resourceId", "")

    diagnostic_setting_name = extract_resource_name_from_id(
        resource_id, "diagnosticSettings", default=""
    )
    if diagnostic_setting_name:
        context["diagnostic_setting_name"] = diagnostic_setting_name

    return context
