from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

NSG_DELETE = "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/DELETE"


def rule(event):
    return event.get("operationName", "").upper() == NSG_DELETE and azure_activity_success(event)


def title(event):
    nsg = event.deep_get("resourceId", default="<UNKNOWN_NSG>")
    caller = event.deep_get("callerIpAddress", default="<UNKNOWN_CALLER>")

    return f"Azure Network Security Group [{nsg}] deleted by [{caller}]"


def severity(event):
    result = event.get("resultType", "")
    if result in ["Success", "Succeeded"]:
        return "HIGH"
    return "DEFAULT"


def alert_context(event):
    return azure_activity_alert_context(event)
