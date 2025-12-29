from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    extract_resource_name_from_id,
)

ALERT_SUPPRESSION_WRITE_OPERATION = "MICROSOFT.SECURITY/ALERTSSUPPRESSIONRULES/WRITE"


def rule(event):
    return all(
        [
            event.get("operationName", "").upper() == ALERT_SUPPRESSION_WRITE_OPERATION,
            azure_activity_success(event),
        ]
    )


def title(event):
    resource_id = event.get("resourceId", "<UNKNOWN_RESOURCE>")

    rule_name = extract_resource_name_from_id(
        resource_id, "alertsSuppressionRules", default="<UNKNOWN_RULE_NAME>"
    )

    return f"Azure Alert Suppression Rule Created or Modified: [{rule_name}]"


def alert_context(event):
    context = azure_activity_alert_context(event)

    resource_id = event.get("resourceId", "")
    rule_name = extract_resource_name_from_id(resource_id, "alertsSuppressionRules", default="")
    if rule_name:
        context["suppression_rule_name"] = rule_name

    return context
