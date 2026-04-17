from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    extract_resource_name_from_id,
)

RUNBOOK_DELETE_OPERATION = "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/DELETE"


def rule(event):
    return event.get(
        "operationName", ""
    ).upper() == RUNBOOK_DELETE_OPERATION and azure_activity_success(event)


def title(event):
    resource_id = event.get("resourceId", "<UNKNOWN_RESOURCE>")

    runbook_name = extract_resource_name_from_id(
        resource_id, "runbooks", default="<UNKNOWN_RUNBOOK_NAME>"
    )

    return f"Azure Automation Runbook Deleted: [{runbook_name}]"


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
