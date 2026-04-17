from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    extract_resource_name_from_id,
)

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
    resource_id = event.get("resourceId", "<UNKNOWN_RESOURCE_ID>")

    runbook_name = extract_resource_name_from_id(
        resource_id, "runbooks", default="<UNKNOWN_RUNBOOK_NAME>"
    )

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

    runbook_name = extract_resource_name_from_id(resource_id, "runbooks", default="")
    if runbook_name:
        context["runbook_name"] = runbook_name

    automation_account_name = extract_resource_name_from_id(
        resource_id, "automationAccounts", default=""
    )
    if automation_account_name:
        context["automation_account_name"] = automation_account_name

    return context
