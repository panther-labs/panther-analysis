from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

AUTOMATION_ACCOUNT_WRITE = "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/WRITE"


def rule(event):
    return event.get(
        "operationName", ""
    ).upper() == AUTOMATION_ACCOUNT_WRITE and azure_activity_success(event)


def title(event):
    resource_id = event.get("resourceId", "<UNKNOWN_RESOURCE>")

    account_name = "<UNKNOWN_ACCOUNT>"
    if resource_id:
        parts = resource_id.split("/")
        if "automationAccounts" in parts:
            try:
                account_name = parts[parts.index("automationAccounts") + 1]
            except (IndexError, ValueError):
                pass

    return f"Azure Automation Account Created: [{account_name}]"


def alert_context(event):
    context = azure_activity_alert_context(event)

    resource_id = event.get("resourceId", "")
    if resource_id:
        parts = resource_id.split("/")
        if "automationAccounts" in parts:
            try:
                context["automation_account_name"] = parts[parts.index("automationAccounts") + 1]
            except (IndexError, ValueError):
                pass

    return context
