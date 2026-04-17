from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    extract_resource_name_from_id,
)

AUTOMATION_ACCOUNT_WRITE = "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/WRITE"


def rule(event):
    return event.get(
        "operationName", ""
    ).upper() == AUTOMATION_ACCOUNT_WRITE and azure_activity_success(event)


def title(event):
    resource_id = event.get("resourceId", "<UNKNOWN_RESOURCE>")

    account_name = extract_resource_name_from_id(
        resource_id, "automationAccounts", default="<UNKNOWN_ACCOUNT>"
    )

    return f"Azure Automation Account Created: [{account_name}]"


def alert_context(event):
    context = azure_activity_alert_context(event)

    resource_id = event.get("resourceId", "")
    account_name = extract_resource_name_from_id(resource_id, "automationAccounts", default="")
    if account_name:
        context["automation_account_name"] = account_name

    return context
