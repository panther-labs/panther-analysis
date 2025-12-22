from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

ALERT_RULES_DELETE = "MICROSOFT.INSIGHTS/ALERTRULES/DELETE"
METRIC_ALERTS_DELETE = "MICROSOFT.INSIGHTS/METRICALERTS/DELETE"


def rule(event):
    operation = event.get("operationName", "").upper()
    return operation in [ALERT_RULES_DELETE, METRIC_ALERTS_DELETE] and azure_activity_success(event)


def title(event):
    alert_rule = event.deep_get("resourceId", default="<UNKNOWN_ALERT>")
    caller = event.deep_get("callerIpAddress", default="<UNKNOWN_CALLER>")

    return f"Azure Alert Rule deleted [{alert_rule}] from [{caller}]"


def alert_context(event):
    return azure_activity_alert_context(event)
