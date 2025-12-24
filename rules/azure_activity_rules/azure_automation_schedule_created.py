from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

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

    schedule_name = "<UNKNOWN_SCHEDULE>"
    if resource_id:
        parts = resource_id.split("/")
        if "schedules" in parts:
            try:
                schedule_name = parts[parts.index("schedules") + 1]
            except (IndexError, ValueError):
                pass

    return f"Azure Automation Schedule Created or Modified: [{schedule_name}] by [{caller}]"


def alert_context(event):
    context = azure_activity_alert_context(event)

    resource_id = event.get("resourceId", "")
    if resource_id:
        parts = resource_id.split("/")
        if "schedules" in parts:
            try:
                context["schedule_name"] = parts[parts.index("schedules") + 1]
            except (IndexError, ValueError):
                pass
        if "automationAccounts" in parts:
            try:
                context["automation_account_name"] = parts[parts.index("automationAccounts") + 1]
            except (IndexError, ValueError):
                pass

    return context
