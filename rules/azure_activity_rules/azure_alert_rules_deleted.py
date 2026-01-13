from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    extract_resource_name_from_id,
)

ALERT_RULES_DELETE = "MICROSOFT.INSIGHTS/ALERTRULES/DELETE"
METRIC_ALERTS_DELETE = "MICROSOFT.INSIGHTS/METRICALERTS/DELETE"


def rule(event):
    operation = event.get("operationName", "").upper()
    return operation in [ALERT_RULES_DELETE, METRIC_ALERTS_DELETE] and azure_activity_success(event)


def title(event):
    alert_rule = event.get("resourceId", "<UNKNOWN_ALERT>")
    return f"Azure Alert Rule deleted [{alert_rule}]"


def alert_context(event):
    context = azure_activity_alert_context(event)

    resource_id = event.get("resourceId", "")
    operation = event.get("operationName", "").upper()

    # Determine resource type based on operation
    if operation == METRIC_ALERTS_DELETE:
        alert_name = extract_resource_name_from_id(resource_id, "metricalerts", default="")
        if alert_name:
            context["alert_rule_name"] = alert_name
            context["alert_type"] = "metric"
    else:
        alert_name = extract_resource_name_from_id(resource_id, "alertrules", default="")
        if alert_name:
            context["alert_rule_name"] = alert_name
            context["alert_type"] = "classic"

    resource_group = extract_resource_name_from_id(resource_id, "resourceGroups", default="")
    if resource_group:
        context["resource_group"] = resource_group

    return context
