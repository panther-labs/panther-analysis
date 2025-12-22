from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

RUNBOOK_DELETE_OPERATION = "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/DELETE"


def rule(event):
    return event.get(
        "operationName", ""
    ).upper() == RUNBOOK_DELETE_OPERATION and azure_activity_success(event)


def title(event):
    resource_id = event.get("resourceId", "<UNKNOWN_RESOURCE>")

    runbook_name = "<UNKNOWN_RUNBOOK>"
    if resource_id:
        parts = resource_id.split("/")
        if "runbooks" in parts:
            try:
                runbook_name = parts[parts.index("runbooks") + 1]
            except (IndexError, ValueError):
                pass

    return f"Azure Automation Runbook Deleted: [{runbook_name}]"


def alert_context(event):
    context = azure_activity_alert_context(event)

    resource_id = event.get("resourceId", "")
    if resource_id:
        parts = resource_id.split("/")
        if "runbooks" in parts:
            try:
                context["runbook_name"] = parts[parts.index("runbooks") + 1]
            except (IndexError, ValueError):
                pass
        if "automationAccounts" in parts:
            try:
                context["automation_account_name"] = parts[parts.index("automationAccounts") + 1]
            except (IndexError, ValueError):
                pass

    return context
