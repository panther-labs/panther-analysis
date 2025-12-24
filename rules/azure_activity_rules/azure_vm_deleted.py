from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

VIRTUAL_MACHINE_DELETE = "MICROSOFT.COMPUTE/VIRTUALMACHINES/DELETE"


def rule(event):
    return event.get(
        "operationName", ""
    ).upper() == VIRTUAL_MACHINE_DELETE and azure_activity_success(event)


def title(event):
    vmname = event.deep_get("resourceId", default="<UNKNOWN_VM>")
    caller = event.deep_get("callerIpAddress", default="<UNKNOWN_CALLER>")

    return f"Azure Virtual Machine deleted [{vmname}] from [{caller}]"


def alert_context(event):
    return azure_activity_alert_context(event)
