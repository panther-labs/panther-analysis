from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

VNET_DELETE = "MICROSOFT.NETWORK/VIRTUALNETWORKS/DELETE"


def rule(event):
    return event.get("operationName", "").upper() == VNET_DELETE and azure_activity_success(event)


def title(event):
    vnet = event.deep_get("resourceId", default="<UNKNOWN_VNET>")
    caller = event.deep_get("callerIpAddress", default="<UNKNOWN_CALLER>")

    return f"Azure Virtual Network deleted [{vnet}] from [{caller}]"


def alert_context(event):
    return azure_activity_alert_context(event)
