from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

DISK_DELETE = "MICROSOFT.COMPUTE/DISKS/DELETE"


def rule(event):
    return event.get("operationName", "").upper() == DISK_DELETE and azure_activity_success(event)


def title(event):
    disk = event.deep_get("resourceId", default="<UNKNOWN_DISK>")
    caller = event.deep_get("callerIpAddress", default="<UNKNOWN_CALLER>")

    return f"Azure disk deleted [{disk}] from [{caller}]"


def alert_context(event):
    return azure_activity_alert_context(event)
