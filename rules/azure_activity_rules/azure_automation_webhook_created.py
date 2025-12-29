from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    extract_resource_name_from_id,
)

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

    webhook_name = extract_resource_name_from_id(
        resource_id, "webhooks", default="<UNKNOWN_WEBHOOK_NAME>"
    )

    return f"Azure Automation Webhook Created: [{webhook_name}]"


def alert_context(event):
    context = azure_activity_alert_context(event)

    resource_id = event.get("resourceId", "")

    webhook_name = extract_resource_name_from_id(resource_id, "webhooks", default="")
    if webhook_name:
        context["webhook_name"] = webhook_name

    automation_account_name = extract_resource_name_from_id(
        resource_id, "automationAccounts", default=""
    )
    if automation_account_name:
        context["automation_account_name"] = automation_account_name

    return context
