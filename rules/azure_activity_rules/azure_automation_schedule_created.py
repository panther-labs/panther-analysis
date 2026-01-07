from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    extract_resource_name_from_id,
)

SCHEDULE_OPERATIONS = [
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/SCHEDULES/WRITE",
]


def rule(event):
    return event.get("operationName", "").upper() in SCHEDULE_OPERATIONS and azure_activity_success(
        event
    )


def title(event):
    resource_id = event.get("resourceId", "<UNKNOWN_RESOURCE>")
    caller = event.get("callerIpAddress", "<UNKNOWN_CALLER>")

    schedule_name = extract_resource_name_from_id(
        resource_id, "schedules", default="<UNKNOWN_SCHEDULE_NAME>"
    )

    return f"Azure Automation Schedule Created or Modified: [{schedule_name}] by [{caller}]"


def alert_context(event):
    context = azure_activity_alert_context(event)

    resource_id = event.get("resourceId", "")

    schedule_name = extract_resource_name_from_id(resource_id, "schedules", default="")
    if schedule_name:
        context["schedule_name"] = schedule_name

    automation_account_name = extract_resource_name_from_id(
        resource_id, "automationAccounts", default=""
    )
    if automation_account_name:
        context["automation_account_name"] = automation_account_name

    return context
