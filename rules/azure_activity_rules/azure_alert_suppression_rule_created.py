from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

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

    # Extract suppression rule name from resourceId if possible
    rule_name = "<UNKNOWN_RULE>"
    if resource_id:
        parts = resource_id.split("/")
        if "alertsSuppressionRules" in parts:
            try:
                rule_name = parts[parts.index("alertsSuppressionRules") + 1]
            except (IndexError, ValueError):
                pass

    return f"Azure Alert Suppression Rule Created or Modified: [{rule_name}]"


def alert_context(event):
    context = azure_activity_alert_context(event)

    # Extract rule name from resourceId
    resource_id = event.get("resourceId", "")
    if resource_id:
        parts = resource_id.split("/")
        if "alertsSuppressionRules" in parts:
            try:
                context["suppression_rule_name"] = parts[parts.index("alertsSuppressionRules") + 1]
            except (IndexError, ValueError):
                pass

    return context
