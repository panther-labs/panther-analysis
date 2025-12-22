from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

AUTOMATION_WEBHOOK_OPERATIONS = [
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/WEBHOOKS/ACTION",
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/WEBHOOKS/WRITE",
]


def rule(event):
    return event.get(
        "operationName", ""
    ).upper() in AUTOMATION_WEBHOOK_OPERATIONS and azure_activity_success(event)


def title(event):
    resource_id = event.get("resourceId", "<UNKNOWN_RESOURCE>")

    webhook_name = "<UNKNOWN_WEBHOOK>"
    if resource_id:
        parts = resource_id.split("/")
        if "webhooks" in parts:
            try:
                webhook_name = parts[parts.index("webhooks") + 1]
            except (IndexError, ValueError):
                pass

    return f"Azure Automation Webhook Created: [{webhook_name}]"


def alert_context(event):
    context = azure_activity_alert_context(event)

    resource_id = event.get("resourceId", "")
    if resource_id:
        parts = resource_id.split("/")
        if "webhooks" in parts:
            try:
                context["webhook_name"] = parts[parts.index("webhooks") + 1]
            except (IndexError, ValueError):
                pass
        if "automationAccounts" in parts:
            try:
                context["automation_account_name"] = parts[parts.index("automationAccounts") + 1]
            except (IndexError, ValueError):
                pass

    return context
