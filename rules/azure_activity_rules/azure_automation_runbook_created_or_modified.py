from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

RUNBOOK_OPERATIONS = [
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/DRAFT/WRITE",
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/WRITE",
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/PUBLISH/ACTION",
]


def rule(event):
    return event.get("operationName", "").upper() in RUNBOOK_OPERATIONS and azure_activity_success(
        event
    )


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

    operation = event.get("operationName", "").upper()
    action = "Modified"
    if "PUBLISH" in operation:
        action = "Published"
    elif "DRAFT" in operation:
        action = "Draft Created"

    return f"Azure Automation Runbook {action}: [{runbook_name}]"


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
